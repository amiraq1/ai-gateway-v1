from __future__ import annotations

import time


def now_epoch() -> int:
    """Return the current time as whole UTC epoch seconds.

    Admin sessions, login attempts, IP rules, and audit rows all use this clock,
    so expiry and rate-limit windows compare values from the same source.
    """
    return int(time.time())
