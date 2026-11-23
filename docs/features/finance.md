---
description: 在本地按年份与关键词汇总调用者提供的收入记录，报告条数、税前、税额与实发，并按月分组；不读取银行流水或校园账务。
---

# 财务查询（`buaa finance`）

`buaa finance` 读取标准输入上的一个 JSON 对象，把它当作调用者提供的个人收入记录，在本地按年份和关键词筛选，输出条数、税前合计、税额合计、实发合计与按月分组。金额一律是整数分。它不访问校园账务系统、不读取银行流水，输出也不构成银行结算凭证。

行为参考 BUAASubnet/UBAA 的 `docs/site/features/finance.md`（`3ac2ebd6c30162cd1ce1fc50964caa25ed22092f`，MIT，© 2026 MooreFoss）；实现为原创代码，没有复制上游实现。来源与许可评估见 [REFERENCES](../REFERENCES.md#buaasubnetubaa)。

## 在哪里找到

- 命令列表：`buaa help` 的 `commands` 中包含 `finance`。
- 机器可读契约：`buaa schema` 输出的 `commands.finance`（`stdin`、`credit`、`totals`、`failure` 四个字段）。
- 分派实现：`src/main.rs` 的 `"finance"` 分支；逻辑在 `src/finance.rs` 的 `query`。
- 验收条目 `finance-income`：[acceptance.json](../../acceptance.json)。当前状态与已知阻塞见 [STATUS](../STATUS.md#ubaa-judge-finance-and-agenda)。
- 同类指南：[希冀作业](judge.md)、[日程与待办](agenda.md)。

## 命令用法

`buaa finance` 只有一种形态：从标准输入读一个 JSON 对象、向标准输出写一个 JSON 对象。它不接受任何参数，加参数（例如 `--online`）会被判为 `invalid_input`（退出码 2）。

### 1. 全量汇总

`records` 必填，最多 500 条，`serial` 在输入内唯一。金额字段 `gross_cents`、`tax_cents`、`net_cents` 是可选的非负整数分。

```sh
buaa finance <<'JSON'
{
  "records": [
    {
      "serial": "S-1",
      "project": "助研酬金",
      "summary": "十一月",
      "gross_cents": 120000,
      "tax_cents": 3600,
      "net_cents": 116400,
      "tax_rate": "3.00",
      "year": 2026,
      "month": 11,
      "recorded_on": "2026-11-15"
    }
  ]
}
JSON
```

输出 `result: projected`、`totals`（`count`、`gross_cents`、`tax_cents`、`net_cents`）和 `months`：每个月一个分组，含该月 `count`、`net_cents` 与逐条明细。任一项缺少某个金额时，只有对应的合计变成 `null`，不会用 0 顶替。

### 2. 按年份与关键词筛选

- `year`：1970–2100，可选
- `query`：1–100 字符，匹配 `project` 或 `summary`

```sh
buaa finance <<'JSON'
{"year": 2026, "query": "助研", "records": []}
JSON
```

筛选决定哪些记录计入合计；`months` 按月升序排列。

### 3. 金额一致性检查

每条明细都带 `amount_consistent`：三项金额齐全时是 `net_cents == gross_cents - tax_cents` 的布尔值，缺任一项时为 `null`。它只做本地算术比对，不推断缺失的税额或税率，也不修正记录。

### 4. 刷新失败不是空账本

当一次刷新失败、但调用者仍持有记录时，传 `refresh_error`（1–300 字符）：

```sh
buaa finance <<'JSON'
{"refresh_error": "本次刷新失败", "records": []}
JSON
```

- 有记录：照常投影，`record_state: offline_retained`，`refresh_error` 原样回显。
- 无记录：`result: refresh_failed`、`record_state: offline_retained`、`totals: null`、`months: []`；输出同时带 `empty_means_no_income: false`，提醒不要把「没读到」当成「没有收入」。

## 注意事项

- 金额单位是整数分；不要传元，也不要传小数字符串。
- `recorded_on` 是 `YYYY-MM-DD` 民用日期；`year` 是 1970–2100；`month` 是 1–12。
- `tax_rate` 是可选字符串，范围 `0`–`100`，最多两位小数（例如 `3`、`3.5`、`0.00`），不是数值。
- `serial` 为 1–64 字符，`project` 和 `summary` 为 1–200 字符且非空。
- 字段名严格：未知字段会被拒绝，错误信息不回显输入内容。
- 输出恒带 `bank_settlement_known: false` 与 `coverage: supplied_records_only`：这些合计是本地汇总，不是银行到账证明。
- 在线只读入口：`buaa finance session --online` 用审阅过的明文 CAS 服务 `http://icw.buaa.edu.cn/checkbuaa.aspx` 登录，再读取 `jump.aspx?sysid=wscx`，命中查询服务时才会登录 `chaxun.icw.buaa.edu.cn/api-zhcx` 并分页读取 `getStudentSRCX`。当前部署把跳转指向 `https://cwc.buaa.edu.cn/xwfw/`（财务处站点），学生收入查询应用不再提供，因此实测输出为 `state: service_unavailable`、`read_completed: false` 和观测到的目标主机与路径，不会伪造任何收入行。
- 已知限制：财务来源 `202.112.137.133` 在本网络于 TLS ClientHello 阶段被重置，而同一主机从北京云端 IP 可以应答，因此在线读取只能经 SSH 隧道到境内出口完成。

## 隐私与离线

- `buaa finance` 恒为离线（`network_performed: false`）；`buaa finance session --online` 只读取收入记录，不读取银行账号，不写任何数据。
- 收入项目名、说明和流水号属于私人数据；不要提交到公开 issue、日志或测试夹具。
- 上游许可：MIT（© 2026 MooreFoss），见 [REFERENCES](../REFERENCES.md#buaasubnetubaa)。
