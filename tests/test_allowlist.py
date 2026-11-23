"""`redir.allowlist` 的验收测试。

15 个测试分别对应 README 中列出的安全缺陷与正常路径。初始状态下每个
测试都会调用尚未实现的桩函数，因此应恰好产生 15 个失败。测试文件是
验收契约，不应修改。
"""

from redir.allowlist import (
    host_allowed,
    is_safe_target,
    normalize,
    parse_target,
    path_allowed,
    redirect_batch,
    sanitize,
    validate_allowlist,
)


def test_normalize_strips_userinfo_and_normalizes_host():
    """缺陷 5：userinfo 不能伪装成真正的 host，同时验证大小写与默认端口。"""
    raw = "HTTPS://good.com@evil.com:443/app"
    assert normalize(raw) == "https://evil.com/app"
    assert host_allowed(raw, ["good.com"]) is False


def test_normalize_removes_tab_and_newline_scheme_obfuscation():
    """缺陷 6：TAB/换行不能把 javascript: 拆成看似无害的字符串。"""
    for raw in ("java\tscript:alert(1)", "java\nscript:alert(1)"):
        assert normalize(raw) == "javascript:alert(1)"
        assert is_safe_target(raw, ["example.com"], ["/"]) is False


def test_parse_target_treats_protocol_relative_url_as_external():
    """缺陷 3：//host 是外部 authority，不是站内相对路径。"""
    target = parse_target("//evil.com/app/x")
    assert target["scheme"] == ""
    assert target["host"] == "evil.com"
    assert target["path"] == "/app/x"
    assert target["relative"] is False
    assert target["protocol_relative"] is True
    assert is_safe_target("//evil.com/app/x", ["good.com"], ["/app"]) is False


def test_parse_target_treats_backslashes_as_protocol_separator():
    """缺陷 4：浏览器把反斜杠当协议分隔符，解析时不能当成普通路径。"""
    raw = r"\\evil.com\app\x"
    target = parse_target(raw)
    assert target["scheme"] == ""
    assert target["host"] == "evil.com"
    assert target["path"] == "/app/x"
    assert target["relative"] is False
    assert target["protocol_relative"] is True
    assert is_safe_target(raw, ["good.com"], ["/app"]) is False


def test_host_allowed_rejects_suffix_lookalike():
    """缺陷 1：evil-example.com 不是 example.com 的子域。"""
    allow = ["example.com"]
    assert host_allowed("https://evil-example.com/app", allow) is False
    assert host_allowed("https://example.com.evil.com/app", allow) is False
    assert host_allowed("https://example.com/app", allow) is True


def test_wildcard_allow_entry_does_not_match_apex():
    """缺陷 2：*.example.com 不能把裸域 example.com 一起放行。"""
    allow = ["*.example.com"]
    assert host_allowed("https://example.com/app", allow) is False
    assert host_allowed("https://api.example.com/app", allow) is True
    assert host_allowed("https://deep.api.example.com/app", allow) is True


def test_path_allowed_uses_slash_boundary_not_raw_startswith():
    """缺陷 7：前缀 /app 不能命中 /application。"""
    assert path_allowed("https://example.com/application", ["/app"]) is False
    assert path_allowed("https://example.com/application/x", ["/app"]) is False
    assert path_allowed("https://example.com/app", ["/app"]) is True
    assert path_allowed("https://example.com/app/x", ["/app"]) is True
    assert path_allowed("https://example.com/app?tab=1", ["/app"]) is True


def test_is_safe_target_rejects_allowed_host_with_dangerous_scheme():
    """缺陷 8：host 合法不代表 scheme 合法，javascript: 必须被拒绝。"""
    raw = "javascript://example.com/app"
    assert is_safe_target(raw, ["example.com"], ["/app"]) is False
    assert is_safe_target("https://example.com/app", ["example.com"], ["/app"]) is True


def test_sanitize_returns_fallback_instead_of_echoing_unsafe_url():
    """缺陷 9：非法目标必须回退，绝不能把原始危险 URL 原样返回。"""
    fallback = "/home"
    for raw in (
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "//evil.com/app",
        r"\\evil.com\app",
        "https://evil.com/app",
    ):
        assert sanitize(raw, fallback) == fallback
    assert sanitize("/app/ok", fallback) == "/app/ok"


def test_validate_allowlist_reports_empty_entry():
    """缺陷 10：空字符串项等于允许任意 host，必须报告配置问题。"""
    issues = validate_allowlist(["", "*", "Example.com", "example.com"], ["", "/app"])
    assert any(issue.startswith("EMPTY_ALLOW:") for issue in issues)
    assert any(issue.startswith("BROAD_WILDCARD:") for issue in issues)
    assert any(issue.startswith("CASE_INCONSISTENT:") for issue in issues)
    assert any(issue.startswith("EMPTY_PREFIX:") for issue in issues)


def test_relative_path_is_safe_when_prefix_matches():
    """补充用例：合法站内相对路径通过，越界路径拒绝。"""
    allow = ["example.com"]
    assert is_safe_target("/app/dashboard?tab=1", allow, ["/app"]) is True
    assert sanitize("/app/dashboard?tab=1", "/home") == "/app/dashboard?tab=1"
    assert is_safe_target("/admin", allow, ["/app"]) is False


def test_allowed_subdomain_passes_and_external_domain_is_rejected():
    """补充用例：白名单子域通过，外部域拒绝。"""
    allow = ["example.com"]
    prefixes = ["/app"]
    assert is_safe_target("https://api.example.com/app/report", allow, prefixes) is True
    assert is_safe_target("https://example.net/app/report", allow, prefixes) is False


def test_javascript_and_data_schemes_are_rejected():
    """补充用例：javascript: 与 data: 均不得作为跳转目标。"""
    for raw in (
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ):
        assert is_safe_target(raw, ["example.com"], ["/app"]) is False


def test_empty_target_uses_fallback():
    """补充用例：空目标不安全，sanitize 返回 fallback。"""
    assert is_safe_target("", ["example.com"], ["/"]) is False
    assert sanitize("", "/home") == "/home"
    assert sanitize("   ", "/home") == "/home"


def test_redirect_batch_matches_independent_single_decisions():
    """补充用例：批量中每个目标的判定与单独调用完全一致，互不影响。"""
    config = {"allow": ["example.com"], "prefixes": ["/app"], "fallback": "/safe"}
    targets = ["https://example.com/app/x", "//evil.com/app/x"]
    batch = redirect_batch(targets, config)

    assert batch["allowed"] == 1
    assert batch["blocked"] == 1
    assert [item["safe"] for item in batch["results"]] == [True, False]
    assert batch["results"][0]["target"] == targets[0]
    assert batch["results"][0]["redirect"] == targets[0]
    assert batch["results"][1]["target"] == targets[1]
    assert batch["results"][1]["redirect"] == "/safe"
    for item in batch["results"]:
        assert item["safe"] == is_safe_target(
            item["target"], config["allow"], config["prefixes"]
        )
