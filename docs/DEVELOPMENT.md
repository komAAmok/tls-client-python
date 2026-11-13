# 开发文档 · Development Guide

面向要改这个仓库的人。介绍性内容在 [`Readme.md`](../Readme.md)，
上游同步规则在 [`UPSTREAM_SYNC.md`](../UPSTREAM_SYNC.md)，
Requests 兼容层的契约在 [`REQUESTS_API.md`](REQUESTS_API.md)。

- [1. 仓库分层](#1-仓库分层)
- [2. 环境搭建](#2-环境搭建)
- [3. 构建原生库](#3-构建原生库)
- [4. 一条命令跑完的验证](#4-一条命令跑完的验证)
- [5. ABI 演进规则](#5-abi-演进规则)
- [6. 缓存键（cache key）](#6-缓存键cache-key)
- [7. 指纹数据的三条生成链](#7-指纹数据的三条生成链)
- [8. 二进制体积约束](#8-二进制体积约束)
- [9. 上游同步流程](#9-上游同步流程)
- [10. 常见陷阱](#10-常见陷阱)

---

## 1. 仓库分层

| 目录 / 文件 | 归属 | 规则 |
| --- | --- | --- |
| 根目录 Go 文件（除下列四个） | **上游** | 只通过上游同步改动 |
| `tcp_fingerprint.go` · `tcp_socket_unix.go` · `tcp_socket_windows.go` · `tcp_socket_darwin_test.go` | 本地 | 可自由改 |
| `profiles/` `bandwidth/` `tests/` `example/` `trust_anchors/` | **上游** | 同上 |
| `tls_client/` | 本地 | Python 包主体 |
| `cffi_binding/` | 本地 | C ABI 层（`main.go` + `build_binding.py`） |
| `third_party/fhttp/` `third_party/brotli/` | 本地 vendor | 有明确 overlay 说明，见各自目录与 `UPSTREAM_SYNC.md` |
| `python_tests/` `tools/` `docs/` | 本地 | 测试、生成器、文档 |

本地特性若必须碰上游文件，改动要最小，并在 `UPSTREAM_SYNC.md` 的
**Local overlay points** 里登记。`AGENTS.md` 是这条规则的简版。

## 2. 环境搭建

需要 Go **1.27+**（`go.mod` 声明 `go 1.27`）、Python 3.8+、gcc。

```bash
# Python 侧
python3 -m venv .venv && .venv/bin/pip install -e . cffi

# Go 侧：仓库用 mise 钉版本，也可以直接用系统 Go
mise install            # 读 mise.toml
go version              # 需要 >= 1.27
```

模块缓存建议留在仓库内，避免污染 HOME（`.gitignore` 已忽略 `.cache/`）：

```bash
export GOMODCACHE="$PWD/.cache/go-mod"
export GOCACHE="$PWD/.cache/go-build"
export GOTMPDIR="$PWD/.cache/go-tmp"
```

> **注意**：这些环境变量和 `HOME` 都必须在**同一条命令**里导出。shell
> 进程是短暂的，`cd` 和 `export` 不会跨调用留存。

## 3. 构建原生库

```bash
python cffi_binding/build_binding.py --lib      # 只编译当前平台
python cffi_binding/build_binding.py            # 编译 + 校验 CFFI 定义
```

产物在 `cffi_binding/dist/`（已被 `.gitignore` 忽略），需要拷进
`tls_client/bin/` 才会被运行时加载：

```bash
cp cffi_binding/dist/tls-client-linux-amd64.so tls_client/bin/
```

构建参数固定为：

```
-buildmode=c-shared -buildvcs=false -trimpath \
-tags=netgo,osusergo -ldflags="-s -w -buildid="
```

`CGO_ENABLED=1` 且 `GOOS`/`GOARCH` 由脚本设置，交叉编译只需在脚本里指定
目标平台。**没有 lite/nano 分级**：始终是 QUIC/HTTP-3 + 完整 profile 目录。

### 各平台二进制

`tls_client/bin/` 下 12 个文件对应 12 个平台。运行时按 OS/arch 自动选，
`TLS_CLIENT_LIB` 可整体覆盖。**改完 Go 源码只有重新编译过的平台才会带上
新 ABI** —— 其余平台加载旧库时，Python 侧按 ABI 版本降级（见第 5 节）。

## 4. 一条命令跑完的验证

这是 PR 前应该跑的全部内容：

```bash
export GOMODCACHE="$PWD/.cache/go-mod" GOCACHE="$PWD/.cache/go-build"

go build ./...
go test . ./profiles ./cffi_binding ./trust_anchors     # 离线，必须全绿

python -m compileall -q tls_client cffi_binding
python -m unittest discover -s python_tests -p "test_*.py"

python tools/gen_chrome_profiles.py --check             # 生成表是否过期
python tools/gen_chrome_fingerprint_presets.py --check
git diff --check                                        # 空白字符
```

`./tests` 包会打真实外网（tls.peet.ws / tls.browserleaks.com），不适合
当门禁；它的指纹期望值取自 **peet.ws**，所以那几个用例在 browserleaks 上会
因为 Akamai 帧格式不同而报错 —— 这是既有的本地适配问题，不是回归。

### 强制一致性守卫

这几个测试存在的唯一目的就是抓跨语言/跨文件漂移，改对应内容时必须同时更新：

| 测试 | 锁定什么 |
| --- | --- |
| `test_cache_key_parity` + `cffi_binding/cachekey_parity_test.go` | Python `_compute_cache_key_hash` ≡ Go `buildCacheKeyFromConfig`，两侧钉同一组哈希向量 |
| `test_cdef_parity` | `_core.py` 手写 CDEF ≡ `build_binding.py` 从 `main.go` 派生的 CDEF |
| `test_export_parity` | CDEF 里声明的每个符号都被 `//export` 且被编译进去 |
| `test_session_signature_parity` | `AsyncSession.__init__` 与 `Session.__init__` 参数完全一致 |
| `test_supported_identifiers` | 引擎注册的每个 identifier 都被 Python 接受 |
| `test_binary_size_guard` | 产物体积 + 源码层"只用解码器"的性质 |
| `test_requests_api_parity` | 生成模块未过期 + 静态扫描通过 |

## 5. ABI 演进规则

C 结构体是**只追加**的。当前 `GetAbiVersion()` 返回 **4**。

| ABI | 内容 | Python 侧行为 |
| --- | --- | --- |
| 1 | 初始 | — |
| 2 | `disable_session_tickets` / `tls_keylog_path` / `root_ca_pem`；`CustomTlsClient.trust_anchors_payload` | 缺字段直接抛错（`_require_abi2`） |
| 3 | 扩展乱序、`h2_disable_priority_frames`、按 dest 选头序、深 TCP 指纹 | 降级到哨兵值 + 一次性 `RuntimeWarning` |
| 4 | `h2_read_idle_timeout_ms` / `h2_ping_timeout_ms` / `response_header_timeout_ms`；`WebsocketOptions.enable_compression` | **静默忽略**（省略只等于回到旧行为） |

新增字段的完整步骤：

1. `cffi_binding/main.go` 的 cgo 前导块里**追加**字段（不要插在中间）。
2. 同文件 `requestConfig` 加 Go 字段，在 `requestConfigFromOptions` 里从 C 拷过来。
3. `GetAbiVersion()` 自增，并在注释里写清新字段。
4. `tls_client/_core.py` 的 `CDEF` 追加同一行；把字段加进
   `_INT_REQUEST_KEYS` / `_ABI*_REQUEST_FIELDS` / `ASYNC_REQUEST_DEFAULT_KEYS`。
5. 两个入口（`Session.execute_request` 与 `AsyncSession` 的同名路径）都要接线：
   签名、`_val` 解析、`opts.<field>` 赋值。
6. 若字段影响传输行为 → 进缓存键（下一节）。
7. 重新生成 `tools/gen_sessions.py` / `gen_requests_surface.py`。
8. 重新编译**每个**要支持该字段的平台库。

`build_binding.py` 的 CDEF 是从 `main.go` **派生**的，没有手抄副本 ——
所以 `main.go` 是唯一真源，`_core.py` 里的 CDEF 只是镜像。

## 6. 缓存键（cache key）

池里的 `HttpClient` 按缓存键复用。键由 Python 预计算并传给 Go，Go 侧有
等价实现作为回退 —— 两侧必须逐字节一致，否则同一个请求会因为"谁先跑"
拿到不同字节。

- 当前格式版本 **8**。
- 追加顺序：版本 3（ABI 2）→ 4（ABI 2.1 H2 旋钮）→ 5（ABI 3）→
  `|dbg|cp`（版本 6）→ `|rit|pit|rht`（版本 8）。
- 键里**故意不包含** `header_order_by_dest` / `header_order_dest` /
  `cookie_crumb` / `default_headers`：前三个是逐请求线行为，
  `default_headers` 已被 `_merge_default_headers` 折进请求头（见
  `UPSTREAM_SYNC.md` 版本 7 的说明）。
- `connect_headers` **在**键里：引擎在拨号时真正读它。

改键 → 必须同时改 Go 与 Python，并重钉两边的向量常量。

## 7. 指纹数据的三条生成链

三条链都是"生成物入库"，用 `--check` 做 CI 门禁。

```bash
python tools/gen_chrome_profiles.py --check                 # → profiles/chrome_captured_*.go
python tools/gen_chrome_fingerprint_presets.py --check      # → tls_client/fingerprints/chrome_full.py
python tools/gen_sessions.py                                # → tls_client/sessions.py
python tools/gen_requests_surface.py                        # → tls_client/_tls_surface.py
```

捕获源是 `tools/_chrome_captures.json`，由
`tools/extract_chrome_captures.py` 从真实握手录下来。加一个新版本的流程：

1. 录一份 capture，追加进 `_chrome_captures.json`。
2. 跑 `gen_chrome_profiles.py`（Go 侧 registry）和
   `gen_chrome_fingerprint_presets.py`（Python 侧 preset）。
3. 若新版本要作为**手写** profile（带 PSK / trust-anchor 微调），另外加进
   `profiles/internal_browser_profiles.go` 和 `_default_headers.py`，
   并在 `_core.py` 的 `ClientIdentifiers` 字面量里补名字。
4. 跑第 4 节的验证。

> **不要手改生成物**。它们顶部都写着 `DO NOT EDIT`；手改会在下次
> `--check` 或重新生成时被覆盖，而且 `test_requests_api_parity` 会红。

## 8. 二进制体积约束

产物体积有预算测试（`test_binary_size_guard`），当前预算 **14,300,000** 字节，
实测 linux/amd64 约 14.07 MB。

想减体积时，先分清"真的是死代码"和"看着像死代码"：

- `-buildmode=c-shared` **强制外部链接**，外部链接会保留完整的接口 itab。
  所以源码层面已经 devirtualize 掉的路径（例如 x/text 的 CJK **编码**表，
  338 KB）在 .so 里**仍然存在**，而同样的源码 `go build .` 是 0 字节。
  `-linkmode=internal` 对 c-shared 不可用。这类"存量税"不要重复尝试。
- 真正能砍的是**根本没有被调用的依赖**：一个只为服务端写的辅助文件、
  一个解析早已废弃协议的包，都可能各自把整套 `net/http` 拉进来。
  历史案例与实测数字见 `UPSTREAM_SYNC.md` 的 *Dependency pruning* 一节。
- 砍依赖时优先改**调用方**，其次才改 vendor。改 vendor 要留
  `OVERLAY.md` 说明删了什么、为什么，并可被 `--check` / 测试验证。

## 9. 上游同步流程

完整规则在 `AGENTS.md`，摘要：

1. 工作区必须干净，打 `backup/pre-upstream-YYYYMMDD`。
2. `git fetch upstream --prune`，然后 **merge**（不 squash、不 rebase）。
3. 保留本地文件，只对账 `UPSTREAM_SYNC.md` 里登记的 overlay 点；
   未冲突的上游文件不要手写。
4. 跑第 4 节验证。
5. 只更新 `UPSTREAM_SYNC.md` 里的同步点与 overlay 清单。

实操上，逐文件三方合并比 `git merge` 更可控：以上一个同步点的上游
tag 为 ancestor、新 tag 为 theirs、工作区为 ours，然后对每个冲突单独判断。
每个被重新应用的 overlay 都值得在 `UPSTREAM_SYNC.md` 里写一句"为什么"，
因为下一轮同步还会遇到同一处。

## 10. 常见陷阱

**符号看起来在，其实没接上。** 引擎支持某个能力（例如 websocket 的
permessage-deflate）不等于 Python 暴露了它。加特性时要沿
`Go 引擎 → C 结构体 → `//export` → CDEF → Python 签名` 这条链走完，
每层都有对应的守卫测试。

**`tls_client.Session` 不是 `_core.Session`。** 有两个同名类：

| 类 | 模块 | 说明 |
| --- | --- | --- |
| `tls_client.Session` | `tls_client/sessions.py` | Requests 兼容门面，**由 `tools/_sessions_body.py` 生成** |
| `tls_client.NativeSession` | `tls_client/_core.py` | 直接对标引擎的原始接口 |

门面把请求转给 `self._native`，所以引擎有、门面没转发的方法在门面上就"消失"
了。今天修的两个问题都属于这类：`stream_to_file` 只在 `_core.Session` 上，
以及 `WebSocketOptions` 缺 `enable_compression` 字段。**加能力时要在门面层
也走一遍**，并且改生成器而不是改生成物 —— 否则 `test_requests_api_parity`
的过期检查会红。

**文档先于实现。** 写文档时逐条对照代码确认；本仓库确实出现过文档宣称
某能力可用、而 CFFI 层没有该字段的情况。

**`SUPPORTED_CLIENT_IDENTIFIERS` 不等于 `DEFAULT_HEADERS` 的键。**
前者是"引擎能做哪些"，后者是"哪些有默认头"。把两者混同会导致引擎注册
的 profile 被 Python 拒绝（历史上 55 个 Chrome 捕获里有 35 个如此）。需要
默认头时走 preset，preset 自带 UA。

**并发路径要读快照。** `_core.py` 里逐请求覆盖必须基于请求构造时的
快照解析，不能读会话当前值 —— 否则并发改标识符会让头与指纹错配。

**句柄表按 ID 匹配，但 ID 来自不同的计数器。** `wsHandles`（客户端）和
`wsConnHandles`（连接）各自用独立计数器，都从 1 开始，所以两个 ID 会撞车。
把连接 ID 传给操作客户端表的函数，删掉的是**另一个还活着的客户端**。加新的
ws 导出时先确认它操作哪张表；`test_websocket_read_pump` 会断言所有 handle
表在 connect/close 循环后回到起始大小。

**"超时"和"对端关闭"必须是两个值。** 都返回 `None` 会让读循环在死连接上
空转，或者把一次安静误判成关闭。

**测试要用本地服务器。** 打外网的测试会随对端行为漂移；能做成
`httptest` / 本地 socket 的，就在本地做。`tests/cookie_jar_test.go`、
`tests/firefox_unsupported_group_test.go`、`test_websocket_compression.py`
都是这个模式。
