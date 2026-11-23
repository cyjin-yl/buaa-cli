---
description: 把调用者提供的希冀作业记录在本地按课程分组、筛选、排序并给出逐题明细，或用一次显式授权在线只读抓取课程作业清单。
---

# 希冀作业（`buaa judge`）

`buaa judge` 读取标准输入上的一个 JSON 对象，把它当作调用者提供的希冀作业记录，在本地完成课程分组、默认「未完成/未过期」视图、排序、搜索和逐题明细。它不访问网络、不提交作业、不下载题目内容。`buaa judge session --online` 是唯一的在线入口：一次 CAS 登录后只读课程清单、每门课的作业索引和有限数量的作业详情页。

行为参考 BUAASubnet/UBAA 的 `docs/site/features/judge.md`（`3ac2ebd6c30162cd1ce1fc50964caa25ed22092f`，MIT，© 2026 MooreFoss）；实现为原创代码。来源与许可评估见 [REFERENCES](../REFERENCES.md#buaasubnetubaa)。

## 在哪里找到

- `buaa help` 的 `commands` 包含 `judge`；`buaa schema` 的 `commands.judge` 给出机器可读契约（`stdin`、`credit`、`filter`、`failure`）。
- 分派在 `src/main.rs` 的 `"judge"` 分支；离线投影是 `src/judge.rs` 的 `query`，在线只读是 `session`。
- 验收条目 `judge-assignments`：[acceptance.json](../../acceptance.json)；状态与阻塞见 [STATUS](../STATUS.md#ubaa-judge-finance-and-agenda)。

## 命令用法

两个命令都从标准输入读一个 JSON 对象、向标准输出写一个 JSON 对象。`buaa judge` 不接受参数，`buaa judge session` 只接受一个可选的 `--online`。`now` 必填，必须是精确到秒的 `+08:00` 时间戳。

1. 离线投影默认视图。`assignments` 必填，最多 200 条，每条最多 100 道题：

```sh
buaa judge <<'JSON'
{
  "now": "2026-11-22T09:00:00+08:00",
  "assignments": [
    {
      "course_id": "algo-2026",
      "course_name": "算法设计与分析",
      "assignment_id": "hw-3",
      "title": "第三次作业",
      "start": "2026-11-18T08:00:00+08:00",
      "due": "2026-11-25T23:59:00+08:00",
      "problems": [
        {"name": "第一题", "score": 10, "max_score": 10, "submitted": true},
        {"name": "第二题", "score": null, "max_score": 20, "submitted": false}
      ]
    }
  ]
}
JSON
```

默认视图丢掉已提交和已过期（`due` 早于 `now`）的作业。输出带 `result: projected`、`coverage: supplied_records_only`、`groups`、`network_performed: false`、`submission_performed: false`；`status` 为 `unknown`/`unsubmitted`/`submitted`/`partial`，并附中文 `status_text`。

2. 调整排序、搜索、可见范围与明细。可选字段：`sort`（`due` 默认 / `start`）、`order`（`asc` 默认 / `desc`）、`query`（1–100 字符，匹配课程名或标题）、`include_completed`、`include_expired`；加 `assignment_id` 则返回 `result: detail`（未命中为 `not_found`）。`include_expired` 只带回过期项，「已提交但未过期」由 `include_completed` 控制。

```sh
buaa judge <<'JSON'
{"now": "2026-11-22T09:00:00+08:00", "sort": "start", "order": "desc", "query": "作业", "assignment_id": "hw-3", "assignments": []}
JSON
```

3. 读取失败的显式表达。用 `read_error`（1–300 字符）代替伪造空清单，输出 `result: read_failed`，`assignments` 与 `groups` 为 `null`：

```sh
buaa judge <<'JSON'
{"now": "2026-11-22T09:00:00+08:00", "read_error": "上游读取超时", "assignments": []}
JSON
```

4. 在线只读（需显式授权）：

```sh
buaa judge session --online <<'JSON'
{
  "authorized": true,
  "username": "<你的学号>",
  "password": "<你的口令>",
  "intent": "LOGIN <你的学号> judge"
}
JSON
```

一次 CAS 登录 `https://judge.buaa.edu.cn/`，先读 `courselist.jsp?courseID=0`；最多 6 门课（每门读课程页和 `assignment/index.jsp`），最多 20 个 `assignment/index.jsp?assignID=...` 详情页。输出是同一套投影，再加 `service: "judge"`、`source: "network"`、`network_performed: true`、`requests_performed`；在线记录的 `problems` 为空，所以状态是 `unknown`、分数为 `null`。`intent` 必须逐字等于 `LOGIN <username> judge`。

## 注意事项

- 时间戳必须写成 `YYYY-MM-DDTHH:MM:SS+08:00`，不接受其他偏移、`Z` 后缀或省略秒。
- `assignment_id` 在输入内唯一；一个 `course_id` 不能对应两个 `course_name`。题目分数必须在 `0..=max_score` 内，未提交的题不能已有分数；有已提交题缺 `score` 时汇总 `my_score` 为 `null`。
- 字段名严格：未知字段被拒绝（`invalid_input`，退出码 2），错误信息不回显输入内容。给 `buaa judge` 加参数（如 `--online`）同样判 `invalid_input`。
- 缺少 `--online` 时 `buaa judge session` 以错误退出且不发送认证请求；不自动刷新、不重试。
- 已知限制：授权账号的课程网格为空，因此按课程解析作业索引与详情页只有合成用例证明；`coursegrading` 是独立的提交流程。

## 隐私与离线

默认完全离线（`network_performed`/`submission_performed` 恒为 `false`）。在线凭据只从标准输入进入进程，不写入 argv、日志、输出或仓库文件；输出会筛查会话/口令回显，命中则报错而不返回结果。课程名、作业标题、题目名属于私人文书内容，不要贴进公开 issue、日志或测试夹具。上游许可：MIT（© 2026 MooreFoss），见 [REFERENCES](../REFERENCES.md#buaasubnetubaa)。
