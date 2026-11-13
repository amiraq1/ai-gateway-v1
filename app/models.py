from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str = Field(min_length=1, max_length=128)
    messages: list[dict[str, Any]] = Field(min_length=1, max_length=256)
    temperature: float | None = Field(default=None, ge=0, le=2)
    top_p: float | None = Field(default=None, ge=0, le=1)
    n: int | None = Field(default=None, ge=1, le=8)
    stream: bool = False
    stop: str | list[str] | None = None
    max_tokens: int | None = Field(default=None, ge=1, le=1_000_000)
    max_completion_tokens: int | None = Field(default=None, ge=1, le=1_000_000)
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    logit_bias: dict[str, float] | None = None
    user: str | None = Field(default=None, max_length=256)
    seed: int | None = None
    response_format: dict[str, Any] | None = None
    tools: list[dict[str, Any]] | None = Field(default=None, max_length=128)
    tool_choice: str | dict[str, Any] | None = None
    parallel_tool_calls: bool | None = None

    @model_validator(mode="after")
    def tokens_not_both(self) -> "ChatCompletionRequest":
        if self.max_tokens is not None and self.max_completion_tokens is not None:
            raise ValueError("Provide only one of max_tokens or max_completion_tokens")
        return self


SUPPORTED_FIELDS = set(ChatCompletionRequest.model_fields)


def provider_payload(request: ChatCompletionRequest, actual_model: str) -> dict[str, Any]:
    extra = set(request.model_extra or {}) - SUPPORTED_FIELDS
    if extra:
        unsupported = ", ".join(sorted(extra))
        raise ValueError(f"Unsupported request parameter(s): {unsupported}")
    payload = request.model_dump(exclude_unset=True, exclude_none=True)
    payload["model"] = actual_model
    return payload
