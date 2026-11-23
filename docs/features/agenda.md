---
description: 在本地把调用者提供的校级安排与个人日程、待办合并，支持北京时间重复规则、备注、冲突提示和 ICS 快照，并可显式在线读取一天校级日程。
---

# 日程与待办（`buaa agenda`）

`buaa agenda` 读取标准输入上的一个 agenda 文档（`school` 校级条目 + `personal` 个人条目）和一个操作，在本地完成视图投影、时间窗筛选、重复展开、增删改、完成/隐藏/备注覆盖、冲突提示与 ICS 导出。校级条目始终由调用者提供，命令不抓取也不修改校园系统。`buaa agenda session --online` 是唯一的在线入口：一次 GSMIS 登录后只读一天的 `portal/queryRcap.do`，从不调用更新或删除端点，也不导出响应正文。

行为参考 BUAASubnet/UBAA 的 `docs/site/features/agenda.md`（`3ac2ebd6c30162cd1ce1fc50964caa25ed22092f`，MIT，© 2026 MooreFoss）；实现为原创代码。来源与许可评估见 [REFERENCES](../REFERENCES.md#buaasubnetubaa)。

## 在哪里找到

- `buaa help` 的 `commands` 包含 `agenda`；`buaa schema` 的 `commands.agenda` 列出 `operations`、`recurrence`、`time`、`sync`、`export`、`session` 的边界。
- 分派在 `src/main.rs` 的 `"agenda"` 分支；本地文档操作是 `src/agenda.rs` 的 `run`，在线只读是 `session`。
- 验收条目 `agenda`：[acceptance.json](../../acceptance.json)；状态与阻塞见 [STATUS](../STATUS.md#ubaa-judge-finance-and-agenda)。

## 命令用法

输入永远是一个 JSON 对象，`now`、`operation`、`school`、`personal` 必填（没有条目传空数组）。`operation` 取值 `project`、`upcoming`、`add`、`update`、`delete`、`overlay`、`export`、`sync`；除 `session` 外不接受命令行参数。时间必须是精确到秒的 `+08:00` 时间戳。所有输出都会回显更新后的 `school`/`personal` 文档并带 `document_changed`、`network_performed: false`、`campus_mutation: false`；命令不写磁盘，由调用者保存输出的文档。

1. 投影与近期视图。`project` 需要 `view`（`list`/`week`/`month`）和 `range_start`/`range_end`（正区间，不超过 400 天）；`upcoming` 不需要区间，固定看 `now` 起 8 天并把未完成的无日期待办提到 `now`。

```sh
buaa agenda <<'JSON'
{
  "now": "2026-11-22T09:00:00+08:00",
  "operation": "project",
  "view": "week",
  "range_start": "2026-11-16T00:00:00+08:00",
  "range_end": "2026-11-23T00:00:00+08:00",
  "school": [
    {
      "id": "course-algo", "source": "course", "title": "算法设计与分析",
      "location": "主楼 201",
      "start": "2026-11-17T08:00:00+08:00", "end": "2026-11-17T09:40:00+08:00"
    }
  ],
  "personal": [
    {"id": "todo-report", "kind": "todo", "title": "提交第三次作业", "due": "2026-11-20T23:59:00+08:00"}
  ]
}
JSON
```

输出 `result: projected`、`view`、`truncated`、`occurrences`（含 `id`、`source`、`kind`、`title`、`location`、`note`、`start`、`end`、`date`、`all_day`、`completed`、`hidden`）。可选过滤：`sources`（`course`、`assignment`、`boya`、`exam`、`seminar`、`checkin`、`sunlight`、`personal`）、`todo_only`、`show_completed`、`show_hidden`、`query`（1–100 字符，匹配标题/地点/备注）。`upcoming` 输出 `result: upcoming`、`window_days: 8`。

2. 增删改与覆盖。`add` 用 `item` 追加一条个人条目；`update` 需要 `scope`（`this`/`following`/`all`）、`target_id`、新 `item`，`this`/`following` 还要给真实存在的 `occurrence`；`delete` 需要 `scope` 和 `target_id`（校级条目不能删，只能隐藏）；`overlay` 需要 `target_id` 和 `completed`/`hidden`/`note` 中至少一个，`note` 最多 2000 字符。

```sh
buaa agenda <<'JSON'
{"now": "2026-11-22T09:00:00+08:00", "operation": "add",
 "school": [], "personal": [],
 "item": {"id": "group-meeting", "kind": "event", "title": "组会",
          "start": "2026-11-18T14:00:00+08:00", "end": "2026-11-18T15:00:00+08:00"}}
JSON
```

新事件与非隐藏的 `source: "course"` 条目重叠时返回 `result: conflict`、`document_changed: false` 并列出 `conflicts`；确认保存再加 `"save_despite_conflict": true`。成功结果为 `saved`/`updated`/`deleted`/`overlayed`。

3. ICS 快照与云同步边界。`export` 与 `project` 一样需要 `view` 和 `range_*`，输出 `result: exported`、`snapshot: true`、`auto_update: false`、`exported`、`ics`、`omitted_undated`；隐藏条目默认省略，完成条目需 `include_completed: true`（或 `show_completed`）。`sync` 固定返回 `result: blocked`、`reason: cloud_sync_unverified`、`document_changed: false`、`network_performed: false`——UBAA 的云快照路径不是已核实的 CLI 契约。

4. 在线只读（需显式授权）：

```sh
buaa agenda session --online <<'JSON'
{
  "authorized": true,
  "username": "<你的学号>",
  "password": "<你的口令>",
  "intent": "LOGIN <你的学号> agenda",
  "day": "20261122"
}
JSON
```

`day` 可选，接受 `YYYYMMDD` 或 `YYYY-MM-DD`，默认北京时间今天。一次 GSMIS CAS 登录、进入研究生门户页，然后只发一次 `portal/queryRcap.do` 读取该日。输出 `result: parsed`、`service: "gsmis"`、`day`、`term_label`、`event_count`、`source_count`、`events`（含 `id`、`origin`、`type_code`、`title`、`start`、`end`、`location`）、`network_performed: true`、`write_operations_performed: false`；`origin` 由 `TYPE` 映射（`0` course、`1` personal、`2` exam、其他 other）。门户页只额外报告 `mentions_finance` 和 `finance_urls`，不导出正文；门户入口非 200 时返回 `result: schedule_endpoint_absent` 并附 `http_status`。

## 注意事项

- `start`/`end`/`due`/`until`/`occurrence` 都必须是 `YYYY-MM-DDTHH:MM:SS+08:00`，其他偏移或省略秒会被拒绝。
- `school` 与 `personal` 各最多 256 条；`id` 为 1–80 个 ASCII 字母、数字或 `_.:@-`，在文档内唯一。
- 校级 `source` 必须是七种之一；`course` 要有正区间的 `start`/`end` 且没有 `due`，其他类型至少一个时间。个人 `kind` 只有 `event`/`todo`：事件需正的 `start`/`end`，待办要么无日期无时间且不重复，要么只有 `due`；全天事件必须在北京时间零点起止。
- 重复规则：`none`、`daily`（`interval` 1–366）、`weekly`（`interval` 1–52、`weekdays` 周一 0 到周日 6）、`weekdays`（周一到周五）、`teaching_week`（`first_monday` 必须是周一，`start_week`/`end_week`/`weekday` 必填且有序，`parity` 为 `all`/`odd`/`even`）、`custom`。`until` 必须晚于首次发生；重复待办必须有 `due`。
- 展开最多 400 次发生，触顶输出 `truncated: true`；冲突检查触顶输出 `conflict_check_truncated: true`。
- 字段名严格：未知字段被拒绝（`invalid_input`，退出码 2），错误信息不回显输入内容；缺少 `--online` 时 `buaa agenda session` 以错误退出且不发送认证请求。
- 已知限制：校级条目必须由调用者提供；授权账号在线读取 `2026-11-22` 解析为第 11 周、0 条事件，`2026-11-16` 曾返回两条 `WID` 为空的记录（该构建丢弃，保留它们的本地 id 兜底只有合成用例证明）。

## 隐私与离线

本地操作完全离线（`network_performed` 与 `campus_mutation` 恒为 `false`，`sync` 也不联网）。在线凭据只从标准输入进入进程，不写入 argv、日志、输出或仓库文件；会话读会筛查口令/会话回显，命中则报错而不返回结果，输出只保留结构化事件。课程名、事件标题、地点和备注属于私人日程数据，不要贴进公开 issue、日志或测试夹具。上游许可：MIT（© 2026 MooreFoss），见 [REFERENCES](../REFERENCES.md#buaasubnetubaa)。
