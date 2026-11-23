# sec-open-redirect

## 题面

登录成功后跳回业务页，安全测试却用几个斜杠就把用户带去了钓鱼站：evil-example.com 被 host 白名单当成自家域；通配条目把裸域本身也放行；双斜杠开头的目标被当成相对路径；反斜杠开头的目标同样被当成路径；带用户信息的目标不剥离，看起来是自家域实际指向外部；制表符和换行被塞进 scheme 里，javascript 协议照样通过；路径前缀用裸 startswith，/app 命中 /application；只校验 host 不校验 scheme，data 协议也能跳；不安全目标直接回显原地址，等于放行；白名单允许空字符串项，等于允许任意目标。redir/allowlist.py 是核心，tests/test_allowlist.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

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
