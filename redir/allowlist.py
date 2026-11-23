"""Open-redirect 防护的 URL 规范化与白名单判定。

本模块只依赖 Python 标准库。所有 host、路径和配置比较都采用零容差策略：
不按裸后缀放行、不做通配模糊、不忽略路径大小写，也不接受浏览器会特殊
处理的字符。失败时一律按“不安全”处理。
"""

from __future__ import annotations

from urllib.parse import urlsplit

# 仅有的可跳转 scheme；空串表示相对/协议相对/反斜杠形式，
# 其安全性由 host 与 path 判定单独把关。
_ALLOWED_SCHEMES = ("", "http", "https")

_EMPTY_TARGET = {
    "scheme": "",
    "host": "",
    "path": "",
    "relative": False,
    "protocol_relative": False,
}


def _clean(raw: str) -> str | None:
    """清洗原始输入：去首尾空白、剔除 TAB/CR/LF、反斜杠归一为斜杠。

    浏览器会忽略 TAB/CR/LF，并把反斜杠当作协议分隔符，因此判定前必须
    先做这层还原，避免 ``java\\tscript:``、``\\\\evil.com`` 之类的混淆。
    非字符串、空串或清洗后为空时返回 ``None``。
    """
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    cleaned = (
        cleaned.replace("\t", "")
        .replace("\r", "")
        .replace("\n", "")
        .replace("\\", "/")
    )
    if not cleaned:
        return None
    return cleaned


def _remove_dot_segments(path: str) -> str:
    """按 RFC 3986 5.2.4 折叠 ``.``/``..`` 段，保留空段与结尾斜杠。"""
    remaining = path
    output: list[str] = []
    while remaining:
        if remaining.startswith("../"):
            remaining = remaining[3:]
        elif remaining.startswith("./"):
            remaining = remaining[2:]
        elif remaining.startswith("/./"):
            remaining = "/" + remaining[3:]
        elif remaining == "/.":
            remaining = "/"
        elif remaining.startswith("/../"):
            remaining = "/" + remaining[4:]
            if output:
                output.pop()
        elif remaining == "/..":
            remaining = "/"
            if output:
                output.pop()
        elif remaining in (".", ".."):
            remaining = ""
        else:
            if remaining.startswith("/"):
                cut = remaining.find("/", 1)
            else:
                cut = remaining.find("/")
            if cut == -1:
                segment, remaining = remaining, ""
            else:
                segment, remaining = remaining[:cut], remaining[cut:]
            output.append(segment)
    return "".join(output)


def _split(raw: str):
    """清洗并解析，返回 ``(cleaned, SplitResult)``；无法解析返回 ``None``。

    访问 ``port`` 以触发坏端口/越界端口的 ValueError，统一按不可解析处理。
    """
    cleaned = _clean(raw)
    if cleaned is None:
        return None
    try:
        parts = urlsplit(cleaned)
        _ = parts.port  # 坏端口在这里抛 ValueError
    except ValueError:
        return None
    return cleaned, parts


def normalize(url: str) -> str:
    r"""把 URL 规范化为可稳定比较的形式。

    契约：
    - 去掉首尾空白，并删除 URL 中任意位置的 TAB、CR、LF。浏览器会忽略
      这些字符，因此 ``java\tscript:`` 必须还原成 ``javascript:``。
    - scheme 与 host 统一小写；去掉 http 的 80 端口和 https 的 443 端口。
    - 丢弃 userinfo（``//user:pass@host`` 中 ``@`` 之前的凭据部分），后续
      只使用真正的 host。这样 ``https://good.com@evil.com`` 的真实 host
      是 ``evil.com``，而不是 ``good.com``。
    - 折叠路径中的 ``.`` 和 ``..`` 段；保留 query 与 fragment。
    - 空串、纯空白、坏端口等无法解析的输入返回空串，不抛异常。
    - 不做百分号解码，不做 host 后缀、通配符、编辑距离等模糊匹配。

    参数:
        url: 待规范化的绝对 URL 或站内路径。

    返回:
        规范化后的字符串；无法解析时返回 ``""``。
    """
    try:
        parsed = _split(url)
        if parsed is None:
            return ""
        _cleaned, parts = parsed

        scheme = parts.scheme.lower()
        hostname = parts.hostname  # urlsplit 已对 host 做小写化
        port = parts.port

        # 重建不含 userinfo 的 authority；仅剥离 http/https 的默认端口。
        netloc = ""
        if hostname is not None:
            host = f"[{hostname}]" if ":" in hostname else hostname
            is_default_port = (
                (scheme == "http" and port == 80)
                or (scheme == "https" and port == 443)
            )
            netloc = host if (port is None or is_default_port) else f"{host}:{port}"

        path = _remove_dot_segments(parts.path)
        suffix = ""
        if parts.query:
            suffix += "?" + parts.query
        if parts.fragment:
            suffix += "#" + parts.fragment

        if netloc:
            head = f"{scheme}://{netloc}" if scheme else f"//{netloc}"
            return head + path + suffix
        if scheme:
            return f"{scheme}:{path}{suffix}"
        return path + suffix
    except Exception:
        return ""


def parse_target(raw: str) -> dict:
    r"""把跳转目标拆成判定所需的字段。

    返回的 dict 至少包含以下键：
    - ``scheme``: 小写 scheme；没有 scheme 时为 ``""``。
    - ``host``: 小写 host（不含 userinfo 和端口）；没有 host 时为 ``""``。
    - ``path``: 去掉 query/fragment 的路径；相对目标和绝对目标都要给出。
    - ``relative``: 无 scheme 且无 authority 时为 ``True``。
    - ``protocol_relative``: 形如 ``//host/...`` 或 ``\\host\...`` 时为
      ``True``；这是外部 authority，不是站内路径。

    解析规则：
    - ``/app/x`` 是站内相对路径，``relative=True``。
    - ``//evil.com/x`` 是协议相对 URL：``scheme=""``、``host="evil.com"``、
      ``path="/x"``，``relative=False``。
    - 反斜杠按浏览器对特殊 scheme 的行为视作斜杠，因此 ``\\evil.com\x``
      同样得到 host ``evil.com``，``relative=False``。
    - 带 scheme 的目标（``https://...``、``javascript:...`` 等）按 scheme
      解析；仅凭 scheme 不判断安全性。
    - 空串或纯空白返回全空字段，``relative=False``。

    参数:
        raw: 原始跳转目标。

    返回:
        包含上述字段的 dict；不抛异常。
    """
    try:
        parsed = _split(raw)
        if parsed is None:
            return dict(_EMPTY_TARGET)
        cleaned, parts = parsed

        scheme = parts.scheme.lower()
        host = parts.hostname or ""
        path = _remove_dot_segments(parts.path)
        # 无 scheme 且以两个及以上 "/" 开头（含 "///host" 这类多斜杠写法，
        # WHATWG 下浏览器同样按外部 authority 处理；urlsplit 会把多余斜杠
        # 误当路径，这里显式纠回）。
        force_protocol_relative = not scheme and cleaned.startswith("//")
        # netloc 非空但 hostname 为空（例如 "//:8080/"）也算外部 authority，
        # 交给上层按损坏目标拒绝，不能落回站内相对路径。
        has_authority = (
            parts.hostname is not None
            or bool(parts.netloc)
            or force_protocol_relative
        )

        return {
            "scheme": scheme,
            "host": host,
            "path": path,
            "relative": not scheme and not has_authority,
            "protocol_relative": not scheme and has_authority,
        }
    except Exception:
        return dict(_EMPTY_TARGET)


def host_allowed(url: str, allow: list[str]) -> bool:
    r"""判断 URL 的真实 host 是否命中白名单。

    契约：
    - 先规范化并解析，取真实 host；无 host（例如普通相对路径）返回
      ``False``。相对路径由 :func:`path_allowed` 和 :func:`is_safe_target`
      单独判断。
    - 普通项 ``example.com`` 匹配 host 完全相同的 ``example.com``，也匹配
      其子域 ``api.example.com``。必须按 DNS 标签边界比较，不能使用裸
      字符串后缀匹配：``evil-example.com`` 和 ``example.com.evil.com``
      都必须拒绝。
    - ``*.example.com`` 只匹配至少一级子域（``api.example.com``、
      ``a.b.example.com``），不匹配裸域 ``example.com``；``*``、``*.com``
      这类过宽配置不授予任何权限。
    - host 与白名单项先统一小写；除此之外容差为 0，不忽略多一个点、少
      一个点、空白或编辑距离。

    参数:
        url: 待检查的 URL 或目标。
        allow: host 白名单项列表，可含 ``*.example.com`` 形式。

    返回:
        命中时 ``True``，否则 ``False``；不抛异常。
    """
    try:
        host = parse_target(url)["host"]
        if not host:
            return False
        for entry in allow:
            if not isinstance(entry, str):
                continue
            item = entry.strip().lower()
            if not item:
                # 空项不授予任何权限；配置问题由 validate_allowlist 报告。
                continue
            if item.startswith("*."):
                base = item[2:]
                # "*" 与 "*.com" 这类只剩一级标签的通配不授予任何权限。
                if "." not in base:
                    continue
                # 必须至少有一级子域，且按 DNS 标签边界命中。
                if host.endswith("." + base) and len(host) > len(base) + 1:
                    return True
            else:
                if host == item or host.endswith("." + item):
                    return True
        return False
    except Exception:
        return False


def path_allowed(url: str, prefixes: list[str]) -> bool:
    r"""判断 URL 的路径是否落在允许的前缀内。

    契约：
    - 路径取规范化后的目标；query 和 fragment 不参与比较。
    - 前缀 ``/app`` 匹配 ``/app``、``/app/``、``/app/x``，但不匹配
      ``/application``；前缀和路径之间必须以 ``/`` 为边界，不能直接
      用 ``startswith`` 判断。
    - 前缀末尾多余的 ``/`` 归一后去掉；``/`` 匹配任意以 ``/`` 开头的
      站内路径。
    - 路径比较区分大小写，容差为 0。``.``/``..`` 先按规范化结果折叠，
      防止 ``/app/../admin`` 借前缀穿越。
    - ``prefixes`` 为空，或其中某项无效时，该项不匹配；空列表返回
      ``False``。

    参数:
        url: 待检查的 URL 或站内路径。
        prefixes: 允许的路径前缀列表。

    返回:
        路径命中任一有效前缀时为 ``True``；不抛异常。
    """
    try:
        path = parse_target(url)["path"]
        if not path:
            return False
        for prefix in prefixes:
            if not isinstance(prefix, str):
                continue
            item = prefix.strip()
            if not item or not item.startswith("/"):
                continue
            item = item.rstrip("/")
            if item == "":
                # 前缀 "/"（或纯斜杠串）：匹配任意根相对站内路径。
                if path.startswith("/"):
                    return True
            elif path == item or path.startswith(item + "/"):
                return True
        return False
    except Exception:
        return False


def is_safe_target(raw: str, allow: list[str], prefixes: list[str]) -> bool:
    r"""综合判断一个跳转目标是否安全。

    依次要求：
    1. 目标非空且可解析；
    2. scheme 只允许空（相对路径、协议相对或反斜杠形式）或 ``http``/
       ``https``；``javascript:``、``data:``、``vbscript:``、``file:`` 等
       其他 scheme 一律拒绝；
    3. 有 host 的目标（绝对 URL、``//host``、``\\host``）必须通过
       :func:`host_allowed`；
    4. path 必须通过 :func:`path_allowed`；站内相对路径也必须落在给定
       前缀内；
    5. 空 host 的绝对 URL、损坏的 authority、无法规范化的目标均返回
       ``False``。

    本函数不抛异常，任何解析失败或异常情况都按不安全处理。

    参数:
        raw: 原始跳转目标。
        allow: host 白名单。
        prefixes: 允许的路径前缀。

    返回:
        目标可安全跳转时 ``True``，否则 ``False``。
    """
    try:
        if not isinstance(raw, str) or not normalize(raw):
            return False
        target = parse_target(raw)
        scheme = target["scheme"]

        # 缺陷 6/8：scheme 白名单，javascript:/data: 等一律拒绝。
        if scheme not in _ALLOWED_SCHEMES:
            return False

        if target["host"]:
            # 缺陷 1/2/5：以剥离 userinfo 后的真实 host 按标签边界判定。
            if not host_allowed(raw, allow):
                return False
        elif scheme or target["protocol_relative"]:
            # 带 scheme 却没有 host、或 authority 损坏（空 host 的 // 形式）。
            return False

        # 缺陷 7：路径必须落在带斜杠边界的前缀内。
        if not path_allowed(raw, prefixes):
            return False
        return True
    except Exception:
        return False


def sanitize(raw: str, fallback: str) -> str:
    r"""无异常地把跳转目标收敛到站内根相对路径。

    本函数没有 host 白名单参数，因此只接受站内根相对路径：
    - 必须以单个 ``/`` 开头，且不能以 ``//`` 或 ``/\`` 开头；
    - 不能包含 scheme、host、userinfo、反斜杠、TAB/CR/LF 或其他控制字符；
    - 必须是可规范化的合法路径。

    满足条件时返回规范化后的站内路径；空目标、危险 scheme、协议相对或
    反斜杠形式、绝对 URL、非字符串输入等一律返回 ``fallback``（原样）。
    本函数绝不把非法输入原样返回，也不抛异常。

    参数:
        raw: 原始跳转目标。
        fallback: 不安全时使用的默认站内页。

    返回:
        安全的站内路径，或 ``fallback``。
    """
    try:
        if not isinstance(raw, str) or not raw:
            return fallback
        # 任何控制字符（含 TAB/CR/LF 与 DEL）都不接受。
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
            return fallback
        # 缺陷 4：反斜杠形式直接拒绝，不允许进入规范化后被还原成 //host。
        if "\\" in raw:
            return fallback

        stripped = raw.strip()
        if not stripped:
            return fallback
        # 缺陷 3：必须以单个 "/" 开头，"//"（协议相对）直接拒绝。
        if not stripped.startswith("/") or stripped.startswith("//"):
            return fallback

        parts = urlsplit(stripped)
        if parts.scheme or parts.netloc or parts.username is not None:
            return fallback

        normalized = normalize(stripped)
        if not normalized or normalized.startswith("//") or not normalized.startswith("/"):
            return fallback
        return normalized
    except Exception:
        return fallback


def validate_allowlist(allow: list[str], prefixes: list[str]) -> list[str]:
    r"""返回配置问题列表；空列表表示没有发现问题。

    每项是带稳定前缀的字符串，顺序为先扫描 ``allow``，再扫描
    ``prefixes``，便于测试和日志检索：
    - ``EMPTY_ALLOW:<index>``: allow 中的空串或纯空白项；
    - ``BROAD_WILDCARD:<index>:<entry>``: 裸 ``*`` 或 ``*.com`` 这类只
      覆盖一级标签的过宽通配；
    - ``CASE_INCONSISTENT:<index>:<entry>``: 含 ASCII 大写字母的项
      （配置必须统一小写，避免“看起来不同、比较时相同”的歧义）；
    - ``EMPTY_PREFIX:<index>``: prefixes 中的空串或纯空白项；
    - ``PREFIX_NOT_ABSOLUTE:<index>:<entry>``: 非空但不以 ``/`` 开头的
      路径前缀。

    不修改传入列表，不抛异常。

    参数:
        allow: host 白名单项。
        prefixes: 路径前缀项。

    返回:
        问题描述字符串列表；没有问题时为空列表。
    """
    issues: list[str] = []
    try:
        for index, entry in enumerate(allow):
            if not isinstance(entry, str):
                continue
            if not entry.strip():
                # 缺陷 10：空项等于允许任意目标，必须暴露出来。
                issues.append(f"EMPTY_ALLOW:{index}")
                continue
            if entry == "*" or (
                entry.startswith("*.") and "." not in entry[2:]
            ):
                issues.append(f"BROAD_WILDCARD:{index}:{entry}")
            if any("A" <= ch <= "Z" for ch in entry):
                issues.append(f"CASE_INCONSISTENT:{index}:{entry}")

        for index, entry in enumerate(prefixes):
            if not isinstance(entry, str):
                continue
            if not entry.strip():
                issues.append(f"EMPTY_PREFIX:{index}")
                continue
            if not entry.startswith("/"):
                issues.append(f"PREFIX_NOT_ABSOLUTE:{index}:{entry}")
    except Exception:
        return issues
    return issues


def redirect_batch(targets: list[str], config: dict) -> dict:
    r"""批量判定并给出每个目标的最终跳转地址；各目标完全独立。

    ``config`` 可包含：
    - ``allow``: host 白名单，默认空列表；
    - ``prefixes``: 路径前缀，默认空列表；
    - ``fallback``: 不安全目标的默认页，默认 ``"/"``。

    返回结构：
    ``{"results": [...], "allowed": <int>, "blocked": <int>}``。

    ``results`` 与 ``targets`` 顺序一致，每项为：
    ``{"target": <原始目标>, "safe": <bool>, "redirect": <str>}``。
    安全目标的 ``redirect`` 是规范化后的目标，不安全目标为
    ``fallback``。每个元素只依赖自身和 config；某个目标失败、异常或
    非法，不会改变其他目标的判定，也不共享可变状态。非字符串 target
    按不安全处理。

    参数:
        targets: 原始跳转目标列表。
        config: 包含 allow、prefixes、fallback 的配置 dict。

    返回:
        包含 results、allowed、blocked 的 dict；不抛异常。
    """
    results: list[dict] = []
    allowed = 0
    blocked = 0
    try:
        if not isinstance(config, dict):
            config = {}
        allow = config.get("allow") or []
        prefixes = config.get("prefixes") or []
        fallback = config.get("fallback", "/")

        for raw in targets:
            try:
                safe = is_safe_target(raw, allow, prefixes)
                if safe:
                    redirect = normalize(raw)
                    # 理论上 safe 时必然可规范化；防御性兜底，绝不回显原地址。
                    if not redirect:
                        safe = False
                        redirect = fallback
                else:
                    redirect = fallback
            except Exception:
                safe = False
                redirect = fallback

            if safe:
                allowed += 1
            else:
                blocked += 1
            results.append(
                {"target": raw, "safe": safe, "redirect": redirect}
            )
    except Exception:
        pass
    return {"results": results, "allowed": allowed, "blocked": blocked}
