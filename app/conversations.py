"""SQLite access for conversations and messages.

Conversation text is stored in SQLite as plain text. Protect the database file
and its backups accordingly. Logs and audit rows never contain message text.

Every query filters by the owning admin user, and every value is a bound
parameter. A turn moves out of `processing` only through a conditional update,
so a retry, a timeout, and a disconnect cannot both finish the same turn.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from .audit import record_audit_event
from .clock import now_epoch
from .database import Database

MAX_USER_MESSAGE_BYTES = 32_768
MAX_ASSISTANT_BYTES = 262_144  # matches the CHECK constraint on messages.content
MAX_CONTEXT_MESSAGES = 40
MAX_CONTEXT_CHARS = 120_000
# A claim older than this is treated as abandoned. It must exceed the longest provider
# stream (the 600 s deadline in chat_routes), so a live stream is never reclaimed.
CLAIM_STALE_SECONDS = 660
DEFAULT_TITLE = "New conversation"
_TITLE_CHARS = 80


class ChatError(Exception):
    """A domain refusal that the route turns into an HTTP error. The message is always generic."""

    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers


@dataclass(frozen=True)
class TurnResult:
    completed: bool
    content: str = ""
    provider_name: str | None = None
    usage: dict[str, Any] | None = None
    error_category: str | None = None
    cancelled: bool = False


@dataclass(frozen=True)
class Turn:
    conversation_id: int
    user_message_id: int
    model_alias: str
    history: tuple[tuple[str, str], ...] = ()
    context_truncated: bool = False
    # The claim this request owns. Only a finish that still matches this value may change the turn.
    claimed_at: int = 0
    replay: dict[str, Any] | None = field(default=None, compare=False)


def trim_history(pairs: list[tuple[str, str]], max_messages: int, max_chars: int) -> tuple[list[tuple[str, str]], bool]:
    """Keep the most recent messages that fit the budget. The context always starts with a user turn."""
    kept: list[tuple[str, str]] = []
    chars = 0
    truncated = False
    for role, content in reversed(pairs):
        if len(kept) >= max_messages or chars + len(content) > max_chars:
            truncated = True
            break
        kept.append((role, content))
        chars += len(content)
    kept.reverse()
    while kept and kept[0][0] != "user":
        kept.pop(0)
        truncated = True
    return kept, truncated


def _usage_value(usage: dict[str, Any] | None, *names: str) -> int | None:
    for name in names:
        value = (usage or {}).get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def _derive_title(message: str) -> str:
    first = next((line for line in message.splitlines() if line.strip()), "").strip()
    cleaned = "".join(ch for ch in first if ch.isprintable())
    return cleaned[:_TITLE_CHARS] or DEFAULT_TITLE


def clean_title(raw: str | None) -> str:
    if raw is None or not raw.strip():
        return DEFAULT_TITLE
    cleaned = "".join(ch for ch in raw.strip() if ch.isprintable())
    return cleaned[:200] or DEFAULT_TITLE


def utf8_size(text: str) -> int | None:
    """UTF-8 byte length of text, or None when it contains lone surrogates and cannot be stored."""
    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:
        return None


# Turns are ordered by the prompt that starts them, with the prompt before its reply.
# Ordering by created_at alone can place a late reply after a later prompt when two
# turns overlap or a retry completes late. The turn key keeps each reply next to its prompt.
_TURN_ORDER = "COALESCE(reply_to_message_id, id), CASE WHEN role = 'user' THEN 0 ELSE 1 END"


def _history(conn: sqlite3.Connection, conversation_id: int) -> tuple[tuple[tuple[str, str], ...], bool]:
    rows = conn.execute(
        f"SELECT role, content FROM messages WHERE conversation_id = ? AND status = 'complete' ORDER BY {_TURN_ORDER}",
        (conversation_id,),
    ).fetchall()
    kept, truncated = trim_history([(str(r["role"]), str(r["content"])) for r in rows],
                                   MAX_CONTEXT_MESSAGES, MAX_CONTEXT_CHARS)
    return tuple(kept), truncated


def _owned_conversation(conn: sqlite3.Connection, owner: int, conversation_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT id, title, model_alias FROM conversations WHERE id = ? AND admin_user_id = ?",
                        (conversation_id, owner)).fetchone()


def _find_turn_by_request_id(conn: sqlite3.Connection, request_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT m.id AS id, m.conversation_id AS conversation_id, m.content AS content, m.status AS status, "
        "m.claimed_at AS claimed_at, c.admin_user_id AS owner "
        "FROM messages AS m JOIN conversations AS c ON c.id = m.conversation_id "
        "WHERE m.request_id = ? AND m.role = 'user'",
        (request_id,),
    ).fetchone()


def _reply_for(conn: sqlite3.Connection, user_message_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, content, model_alias, provider_name, prompt_tokens, completion_tokens, total_tokens "
        "FROM messages WHERE reply_to_message_id = ? AND role = 'assistant' AND status = 'complete'",
        (user_message_id,),
    ).fetchone()


def create_conversation(db: Database, owner: int, title: str | None, model_alias: str,
                        now: int | None = None) -> dict[str, Any]:
    current = now_epoch() if now is None else now
    with db.transaction() as conn:
        cursor = conn.execute(
            "INSERT INTO conversations(admin_user_id, title, model_alias, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (owner, clean_title(title), model_alias, current, current),
        )
        conversation_id = int(cursor.lastrowid or 0)
    return conversation_summary(db, owner, conversation_id)


def conversation_summary(db: Database, owner: int, conversation_id: int) -> dict[str, Any]:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT id, title, model_alias, created_at, updated_at, archived_at FROM conversations "
            "WHERE id = ? AND admin_user_id = ?",
            (conversation_id, owner),
        ).fetchone()
    return dict(row) if row else {}


def list_conversations(db: Database, owner: int, limit: int, offset: int) -> list[dict[str, Any]]:
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT id, title, model_alias, created_at, updated_at, archived_at FROM conversations "
            "WHERE admin_user_id = ? ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?",
            (owner, limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]


def load_conversation(db: Database, owner: int, conversation_id: int, limit: int) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    """Return the conversation and its most recent messages in chronological order, or None if not owned."""
    with db.connect() as conn:
        row = conn.execute(
            "SELECT id, title, model_alias, created_at, updated_at, archived_at FROM conversations "
            "WHERE id = ? AND admin_user_id = ?",
            (conversation_id, owner),
        ).fetchone()
        if row is None:
            return None
        rows = conn.execute(
            "SELECT id, role, content, status, model_alias, provider_name, error_category, request_id, "
            "reply_to_message_id, created_at, completed_at, prompt_tokens, completion_tokens, total_tokens "
            "FROM ("
            "SELECT *, COALESCE(reply_to_message_id, id) AS turn_key, "
            "CASE WHEN role = 'user' THEN 0 ELSE 1 END AS role_order "
            "FROM messages WHERE conversation_id = ? ORDER BY turn_key DESC, role_order DESC LIMIT ?"
            ") ORDER BY turn_key ASC, role_order ASC",
            (conversation_id, limit),
        ).fetchall()
    return dict(row), [dict(item) for item in rows]


def delete_conversation(db: Database, owner: int, conversation_id: int, *, ip_address: str | None,
                        user_agent: str | None, now: int | None = None) -> bool:
    current = now_epoch() if now is None else now
    with db.transaction() as conn:
        cursor = conn.execute("DELETE FROM conversations WHERE id = ? AND admin_user_id = ?",
                              (conversation_id, owner))
        if cursor.rowcount != 1:
            return False
        record_audit_event(conn, action="chat.conversation.delete", admin_user_id=owner,
                           target=f"conversation:{conversation_id}", ip_address=ip_address,
                           user_agent=user_agent, now=current)
    return True


def prepare_turn(db: Database, owner: int, conversation_id: int | None, model_alias: str, message: str,
                 request_id: str | None, now: int) -> Turn:
    """Create or resume the user turn for one request. Every decision is made inside one write transaction."""
    stale_before = now - CLAIM_STALE_SECONDS
    with db.transaction() as conn:
        if request_id is not None:
            existing = _find_turn_by_request_id(conn, request_id)
            if existing is not None:
                if (int(existing["owner"]) != owner
                        or (conversation_id is not None and int(existing["conversation_id"]) != conversation_id)
                        or str(existing["content"]) != message):
                    raise ChatError(409, "request_id_conflict", "This request id was already used for a different message.")
                if existing["status"] == "complete":
                    reply = _reply_for(conn, int(existing["id"]))
                    if reply is None:
                        raise ChatError(409, "request_id_conflict", "This request id cannot be replayed.")
                    replay = {"id": int(reply["id"]), "content": str(reply["content"]),
                              "model_alias": str(reply["model_alias"]),
                              "provider_name": reply["provider_name"],
                              "usage": {"prompt_tokens": reply["prompt_tokens"],
                                        "completion_tokens": reply["completion_tokens"],
                                        "total_tokens": reply["total_tokens"]}}
                    return Turn(conversation_id=int(existing["conversation_id"]),
                                user_message_id=int(existing["id"]), model_alias=model_alias, replay=replay)
                in_flight = existing["status"] == "processing" and int(existing["claimed_at"] or 0) > stale_before
                reclaimed = False
                if not in_flight:
                    cursor = conn.execute(
                        "UPDATE messages SET status = 'processing', claimed_at = ?, completed_at = NULL, error_category = NULL "
                        "WHERE id = ? AND role = 'user' AND (status IN ('failed', 'cancelled') "
                        "OR (status = 'processing' AND claimed_at <= ?))",
                        (now, int(existing["id"]), stale_before),
                    )
                    reclaimed = cursor.rowcount == 1
                if in_flight or not reclaimed:
                    raise ChatError(409, "request_in_progress", "This request is still being processed.",
                                    {"Retry-After": "2"})
                history, truncated = _history(conn, int(existing["conversation_id"]))
                return Turn(conversation_id=int(existing["conversation_id"]), user_message_id=int(existing["id"]),
                            model_alias=model_alias, history=history, context_truncated=truncated, claimed_at=now)

        if conversation_id is not None:
            if _owned_conversation(conn, owner, conversation_id) is None:
                raise ChatError(404, "conversation_not_found", "Conversation was not found.")
            target = conversation_id
        else:
            cursor = conn.execute(
                "INSERT INTO conversations(admin_user_id, title, model_alias, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (owner, _derive_title(message), model_alias, now, now),
            )
            target = int(cursor.lastrowid or 0)
        cursor = conn.execute(
            "INSERT INTO messages(conversation_id, role, content, status, model_alias, request_id, created_at, claimed_at) "
            "VALUES (?, 'user', ?, 'processing', ?, ?, ?, ?)",
            (target, message, model_alias, request_id, now, now),
        )
        user_message_id = int(cursor.lastrowid or 0)
        conn.execute("UPDATE conversations SET updated_at = ? WHERE id = ?", (now, target))
        history, truncated = _history(conn, target)
    return Turn(conversation_id=target, user_message_id=user_message_id, model_alias=model_alias,
                history=history, context_truncated=truncated, claimed_at=now)


def finish_turn(db: Database, turn: Turn, result: TurnResult, now: int | None = None) -> int | None:
    """Record the outcome of one turn. Returns the assistant message id when a reply was stored.

    Only the request that claimed the turn can finish it, and only while that claim
    still matches. A reclaimed turn, a second finish, or a finish after the
    conversation was deleted changes nothing. A cancelled turn never stores a reply,
    even when the provider had already finished.
    """
    current = now_epoch() if now is None else now
    with db.transaction() as conn:
        if result.cancelled:
            _mark(conn, turn, "cancelled", "client_disconnected", current)
            return None
        if result.completed and result.content:
            size = utf8_size(result.content)
            if size is None or size > MAX_ASSISTANT_BYTES:
                problem = "provider_malformed_response" if size is None else "provider_response_too_large"
                _mark(conn, turn, "failed", problem, current)
                return None
            cursor = conn.execute(
                "UPDATE messages SET status = 'complete', completed_at = ?, claimed_at = NULL, error_category = NULL "
                "WHERE id = ? AND status = 'processing' AND claimed_at = ?",
                (current, turn.user_message_id, turn.claimed_at),
            )
            if cursor.rowcount != 1:
                return None
            usage = result.usage
            inserted = conn.execute(
                "INSERT INTO messages(conversation_id, role, content, status, model_alias, provider_name, "
                "reply_to_message_id, created_at, completed_at, prompt_tokens, completion_tokens, total_tokens) "
                "VALUES (?, 'assistant', ?, 'complete', ?, ?, ?, ?, ?, ?, ?, ?)",
                (turn.conversation_id, result.content, turn.model_alias, result.provider_name,
                 turn.user_message_id, current, current,
                 _usage_value(usage, "prompt_tokens", "input_tokens"),
                 _usage_value(usage, "completion_tokens", "output_tokens"),
                 _usage_value(usage, "total_tokens")),
            )
            conn.execute("UPDATE conversations SET model_alias = ?, updated_at = ? WHERE id = ?",
                         (turn.model_alias, current, turn.conversation_id))
            return int(inserted.lastrowid or 0)
        category = result.error_category or ("provider_empty_response" if result.completed
                                             else "provider_stream_incomplete")
        _mark(conn, turn, "failed", category, current)
    return None


def _mark(conn: sqlite3.Connection, turn: Turn, status: str, category: str, now: int) -> None:
    """Leave processing for a terminal status. Does nothing unless this claim still owns the turn."""
    conn.execute(
        "UPDATE messages SET status = ?, error_category = ?, completed_at = ?, claimed_at = NULL "
        "WHERE id = ? AND status = 'processing' AND claimed_at = ?",
        (status, category, now, turn.user_message_id, turn.claimed_at),
    )


def replay_payload(turn: Turn) -> dict[str, Any]:
    replay = turn.replay or {}
    return {"id": replay.get("id"), "content": replay.get("content", ""),
            "model_alias": replay.get("model_alias", turn.model_alias),
            "provider_name": replay.get("provider_name"), "usage": replay.get("usage") or {}}
