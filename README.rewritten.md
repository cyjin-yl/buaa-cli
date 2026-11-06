buaa-cli — BUAA campus service client
====================================

SYNOPSIS
--------

    buaa <command> [<args>] [--online]

DESCRIPTION
-----------

Command-line client for BUAA campus services. Reads campus announcements,
classroom schedules, course materials, and authenticated account data.
All network access is opt-in via --online. Credentials arrive through
protected stdin only.

CAPABILITIES
------------

| Command | Service | Online | Status |
|---------|---------|--------|--------|
| smart session | 空教室/图书馆 | CAS | live-verified |
| timetable session | 研究生课表 | CAS | partial (endpoint 403) |
| boya session | 博雅课程 | CAS | partial (upstream error) |
| ihome session | iHome 消息 | CAS | live-verified (20 entries) |
| organizations list | 院系目录 | public | live-verified |
| announcements | 院系公告 | public | live-verified |
| physics-reference | 物理资料 | public | live-verified |
| departments | 院系资料 | public | live-verified |
| welearn | 学习平台 | public | partial |
| recordings | 课堂录制 | CAS | partial |
| shuttle | 校车 | — | pending |
| electricity | 电费 | — | pending |
| checkin | 签到 | — | pending |
| coursegrading | 判题 | — | pending |
| enrol | 选课 | — | pending |
| drive | 云盘 | — | pending |
| evaluation | 评教 | — | pending |

ENVIRONMENT
-----------

HOME           Governor state directory (0700). Contains durable account
               safety state: auth latches, cooldowns, request pacing.

SECURITY
--------

- Credentials arrive through protected stdin as JSON; never argv, logs,
  or persistent storage.
- Cookie values are zeroized on drop; invocation-only, never replayed
  beyond the reviewed scope.
- HTTP 429 without Retry-After imposes a 30-minute cooldown.
- Auth rejection, CAPTCHA and lock signals latch. One attempt per
  deliberate operator resume; no automatic retry.
- All mutations require exact typed intent, immutable preview,
  plan/commit separation, and authorized postcondition checks.

BUILD
-----

    agent-heavy sh scripts/cargo-locked build
    agent-heavy sh scripts/cargo-locked test --lib
    agent-heavy sh scripts/cargo-locked test --tests

All Cargo commands hold a process-shared lock. CARGO_BUILD_JOBS=1.

EXAMPLES
--------

    # Read campus directory (public, no auth)
    buaa organizations list --online

    # Smart classrooms with credentials
    echo '{"authorized":true,"username":"...","password":"...","intent":"LOGIN ... smart classrooms","read":{"service":"classrooms","enabled":true,"campus_id":1,"date":"2026-11-06"}}' | buaa smart session --online

    # Timetable with credentials
    echo '{"authorized":true,"username":"...","password":"...","intent":"LOGIN ... timetable","read":{"operation":"xskb","enabled":true,"xnxqdm":"20242"}}' | buaa timetable session --online

    # Boya with credentials
    echo '{"authorized":true,"username":"...","password":"...","intent":"LOGIN ... boya","read":{"operation":"semester_courses","query":{"pageNumber":0,"pageSize":20}}}' | buaa boya session --online

    # iHome with credentials
    echo '{"authorized":true,"username":"...","password":"...","intent":"LOGIN ... ihome","read":{"operation":"list","enabled":true}}' | buaa ihome session --online
