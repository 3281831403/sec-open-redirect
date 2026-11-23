"""Open-redirect 白名单练习包。"""

from .allowlist import (
    host_allowed,
    is_safe_target,
    normalize,
    parse_target,
    path_allowed,
    redirect_batch,
    sanitize,
    validate_allowlist,
)

__all__ = [
    "normalize",
    "parse_target",
    "host_allowed",
    "path_allowed",
    "is_safe_target",
    "sanitize",
    "validate_allowlist",
    "redirect_batch",
]
