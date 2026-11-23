---
description: buaa-cli 的校园功能指南索引：希冀作业、财务查询、日程与待办，每个功能都有本地契约与显式在线入口。
---

# 校园功能指南

以下三个功能的行为参考 BUAASubnet/UBAA 的 `docs/site/features/`
（`3ac2ebd6c30162cd1ce1fc50964caa25ed22092f`，MIT，© 2026 MooreFoss），
实现为原创代码，未复制上游实现。来源与许可评估见
[REFERENCES](../REFERENCES.md#buaasubnetubaa)。

默认全部离线：命令从标准输入读取调用者提供的记录，在本地投影。只有两处显式
`--online` 入口会访问校园服务，且都只读一次、有上限、不导出响应正文。

| 功能 | 命令 | 状态 |
| --- | --- | --- |
| [希冀作业](judge.md) | `buaa judge`、`buaa judge session --online` | 本地投影已实现；在线只读已验证到「授权账号课程列表为空」这一步，逐课程解析只有离线样例证明 |
| [财务查询](finance.md) | `buaa finance` | 仅本地汇总；财务站点在本网络下 TLS 握手被重置，没有在线读取 |
| [日程与待办](agenda.md) | `buaa agenda`、`buaa agenda session --online` | 本地投影已实现；在线只读已验证到「解析出第11周、当天 0 条」这一步 |

配套材料：

- [STATUS](../STATUS.md)：带日期的证据与阻塞项。
- [acceptance.json](../../acceptance.json)：机器可读的验收投影。
- [README](../../README.md)：安装、构建、发布边界与命令总表。
