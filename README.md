# sec-open-redirect

## 题面

登录成功后跳回业务页，安全测试却用几个斜杠就把用户带去了钓鱼站：`evil-example.com` 被 host 白名单当成 `example.com` 放行；`*.example.com` 连裸域 `example.com` 也一起放行；协议相对地址 `//evil.com` 被当成站内相对路径；反斜杠写法 `\\evil.com` 被浏览器解释成协议分隔符却被当作普通路径；带 userinfo 的 `https://good.com@evil.com` 被认成 `good.com`；URL 里的制表符/换行把 `javascript:` 拆开后绕过 scheme 检查；路径前缀 `/app` 顺带放行 `/application`；综合判定只查 host 不查 scheme，让 `javascript:` 通行；拒绝时又把原始危险 URL 原样返回；白名单里的空字符串项等价于允许任意 host。redir/allowlist.py 是核心，tests/test_allowlist.py 15个红。要修的是：按零容差补齐规范化、目标解析、host/路径白名单、综合判定与配置校验，危险目标统一回退到默认页，并保证批量判定彼此独立。

## 运行方式

在仓库根目录执行：

```bash
python -m pytest tests -q
```

初始状态必须恰好是 `15 failed`，且不能出现 collection error、import error 或 syntax error；所有失败都应来自 `redir/allowlist.py` 的 `NotImplementedError`。实现完成后应为 `15 passed`。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## tests 不可修改

`tests/test_allowlist.py` 是固定的验收契约，不得修改、删除、跳过或参数化。只能实现 `redir/allowlist.py`，用测试结果验证修复，不能通过改动测试来改变初始的 `15 failed`。
