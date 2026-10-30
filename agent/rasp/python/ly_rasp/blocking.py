"""Central detection reporting and block enforcement.

Every hook funnels through :func:`handle_detection` so the blocked/would_block
outcome is derived from the same signed policy facts as the reporter. Blocking
is only possible when the signed policy mode is ``block``, the server promoted
it (``block_on_hit``) and the policy has not expired. In dry-run the detection
is still reported with ``would_block=true`` and the original call proceeds.
"""
from __future__ import annotations

from typing import Any, Optional

from .config import effective_mode, get_config, should_block
from .correlation import category_for_sink, claim_event


class RASPBlockedError(PermissionError):
    """Raised when a promoted RASP policy blocks the protected operation."""

    def __init__(self, attack_type: str, function: str) -> None:
        super().__init__(f"LyFlow RASP blocked {attack_type} in {function}")
        self.attack_type = attack_type
        self.function = function


def handle_detection(
    event_type: str,
    result: dict,
    func_name: str,
    args: Any,
    enforce: bool = True,
) -> None:
    config = get_config()
    blocked = bool(enforce and should_block(config))
    would_block = bool(
        enforce
        and config is not None
        and effective_mode(config) == 'block'
        and not blocked
    )
    details = dict(result)
    details['hooked_function'] = func_name
    details['args_preview'] = str(args)[:200]
    details['blocked'] = blocked
    details['would_block'] = would_block
    details['action'] = 'block' if blocked else 'log'
    details['mode'] = 'protect' if blocked else ('dry_run' if would_block else 'monitor')

    from .reporter import get_reporter
    reportable = claim_event(category_for_sink(event_type))
    reporter = get_reporter()
    if reporter is not None and reportable:
        reporter.report({'type': event_type, 'details': details,
                         'blocked': blocked, 'would_block': would_block,
                         'action': details['action'], 'mode': details['mode']})
    if blocked:
        raise RASPBlockedError(event_type, func_name)
