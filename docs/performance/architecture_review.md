# 架构审查 · Architecture Review

> 本文件只记录从当前仓库真实代码与真实测量中得到的事实。未验证的内容标记 **待验证**。
>
> 采集环境：`Linux x86_64`，8 核（Intel i7-14650HX），Python 3.12.3，Go 1.27.4，gcc 13.3.0，
> 仓库 `tls-client-python`。共享库 `tls_client/bin/tls-client-linux-amd64.so` 由 CI
> 自动重建（**每次重建 md5 都会变**，14,102,944 字节，ABI 4）。
> 审计当日的本地构建产物是 14,095,240 字节，与本仓库源码重建后逐字节相同；
> CI 产物 ABI 与导出符号集与之完全一致，§4 有独立校验。
> 复现实验时请记录当时的 md5，不要跨轮次混用不同构建。

---

## 1. 目录与归属

| 路径 | 归属 | 作用 |
| --- | --- | --- |
| `tls_client/_core.py`（5,446 行） | 本地 | CFFI 绑定 + `Session`/`AsyncSession` 原生层 |
| `tls_client/sessions.py`（982 行） | 本地 | requests 兼容 `Session` 门面 |
| `tls_client/adapters.py` | 本地 | `PreparedRequest` → 原生层 |
| `tls_client/models.py` | 本地 | requests 对象模型 |
| `cffi_binding/main.go`（2,780 行） | 本地 | C ABI 层：`//export` 函数、请求/响应编组、客户端池 |
| 根目录 Go 文件（除 4 个 `tcp_*`） | **上游** | TLS/HTTP 引擎本体（`client.go`、`roundtripper.go` …） |
| `third_party/fhttp`、`third_party/brotli` | 本地 vendor | 有 overlay 说明 |

约束来自 `AGENTS.md` 与 `UPSTREAM_SYNC.md`：上游文件默认只读，本地改动必须最小并登记到
**Local overlay points**。本次所有改动都落在本地区域（`tls_client/`、`benchmarks/`、
`docs/`），**没有触碰任何上游文件**。

---

## 2. 真实调用链

### 2.1 同步请求

```
Session.get()                     tls_client/sessions.py  →  _tls_surface.py:872
  └─ Session.request()             _tls_surface.py:764
       └─ _dispatch_request()      sessions.py:779
            ├─ Request(...)        models.py
            ├─ prepare_request()   sessions.py:741        ← 约 152 µs
            ├─ merge_environment_settings()  sessions.py:894 ← 约 66 µs
            └─ send()              sessions.py:442  →  adapters.py:186
                 └─ NativeSession.execute_request()  _core.py:3262
                      ├─ _snapshot_selected_defaults()  _core.py:2240
                      ├─ _merge_default_headers()       _core.py:1629
                      ├─ _build_headers() ×4            _core.py:1566
                      ├─ _build_string_array() ×3       _core.py:1672
                      ├─ _compute_cache_key_hash()      _core.py:1932
                      ├─ ffi.new("RequestOptions *")
                      └─ lib.ExecuteRequest(opts)  ──► C ABI
```

### 2.2 C ABI 与 Go

```
ExecuteRequest(opts)              cffi_binding/main.go:2044
  ├─ requestConfigFromOptions()   main.go:625   (C.GoString ×10 ++，body 零拷贝借用)
  ├─ getOrCreateClientFromConfig()main.go:1466  (clientPool sync.Map + cacheKeyHash)
  ├─ http.NewRequest + header 处理 main.go:1757
  ├─ client.Do(req)               main.go:1797  ← 网络 I/O
  ├─ readBodyToCHeap()            main.go:517   (Content-Length 已知时直接读进 C 堆)
  ├─ packResponseArena()          main.go:1937  (单次 malloc：HttpHeader 数组 + 字符串 arena)
  └─ return *C.ResponseResult     (C.malloc 结构体)
```

### 2.3 响应回流

```
*C.ResponseResult
  └─ ffi.gc(raw_res, lib.FreeResponse)      _core.py:3786
       └─ _unpack_c_response()              _core.py:2146
            ├─ ffi.buffer(raw_res.body, blen)[:]   → Python bytes（一次复制）
            ├─ 头表 ffi.string ×2/条
            └─ Response(...)
                 └─ adapters.py:243  response._content = native.content
```

**关键事实**：`Response._content` 与 `native.content` 是同一对象（没有第二次复制）；
`io.BytesIO(native.content)` 只是包装（`BytesIO(b"…")` 实测 0.1–0.8 µs，不复制）。

### 2.4 异步请求

```
AsyncSession.get()                _core.py:5192
  └─ _execute_async()             _core.py:4598
       ├─ 同上全套编组（**在事件循环线程上**）  ← 约 210 µs Python
       ├─ future = loop.create_future()
       ├─ _pending_requests[id] = (future, keep_alive, handle, self)
       ├─ lib.RequestAsync(opts, id, callback)  main.go:2229
       │    ├─ requestConfigFromOptions(opts, copyBody=true)  ← C.GoBytes 复制 body
       │    └─ go func(){ result := executeRequestFromConfig(cfg); invoke_async_callback(...) }
       └─ await future
            ↑ Go goroutine 完成 → CFFI callback（Go OS 线程，持 GIL 极短）
              └─ loop.call_soon_threadsafe(_resolve_async_response, …)
                   └─ _unpack_c_response()  ← **在事件循环线程上执行**
```

---

## 3. 连接池

* Go 侧有一个**进程级** client 池：`clientPool sync.Map`，键是 Python 预计算的
  `cache_key_hash`（格式版本 8，见 `_core.py:1932` 与 `main.go:1224`）。
* 容量：`SetPoolMaxEntries`，默认 1024，LRU 淘汰（`evictLRUOverCapLocked`，`main.go:424`）。
* TTL：默认 300 s，扫描间隔 60 s（`evictStaleEntries`，`main.go:343`）。
* **每个 Session 不持有自己的 Transport**：同配置 Session 共享同一个 pooled client，
  因此共享连接池。`adapters.close()` 故意不调用 `ClearClientPool()`（否则会清掉别的会话的连接）。
* 不同 TLS 指纹/代理/超时等产生不同 cache key → 不同 pooled client → 不同连接池，隔离正确。

---

## 4. 原生构建

`cffi_binding/build_binding.py:485`：

```
CGO_ENABLED=1 go build -buildmode=c-shared -buildvcs=false -trimpath \
  -tags=netgo,osusergo -ldflags="-s -w -buildid=" -o <lib> .
```

* 符号表与调试信息**已经剥离**（`-s -w`），build id 已清空，路径已 trim。
* `profile` tag 才启用 `runtime/pprof`、`runtime/debug`（`introspect_profile.go`），
  发布构建不带（`_require_profile_build()` 会明确报错而不是返回 0）。
* `.so` 段体积（`readelf -SW`）：`.text` 5.72 MB、`.rodata` 0.46 MB、
  `.gopclntab` **3.99 MB**、`.data.rel.ro` 1.23 MB。
  `.gopclntab`（Go 运行期符号表，panic 栈/反射需要）是剥离后剩下的最大块——
  删掉它会让 panic 栈失去函数名，属于功能退化，**未做**。
* CFFI 侧是 **ABI mode**（`ffi.dlopen` + 运行期 `ffi.cdef`），不是 API mode；
  因此不存在编译期生成的 C 扩展模块，wheel 里只有预编译的 `.so`。

---

## 5. 实测出的真实瓶颈（详见 `bottleneck_analysis.md`）

| 层 | 每请求成本 | 占单线程全程 |
| --- | --- | --- |
| Go 引擎（`client.Do` + 读体） | 约 600–930 µs | **约 65 %** |
| CGO 进出边界 + Python 编组 | 约 170–250 µs | 约 20 % |
| requests 兼容层（prepare + env） | 约 210 µs | 约 15 % |
| 响应体 UTF-8 解码（旧实现，10 MiB） | 1.2 ms | 见下 |

关于 `C.GoString` 与 FFI：把 3000 次请求全部放进**一次** CGO 调用（`BenchInline`）
测得 996–1089 µs/req，与每请求一次 CGO 的 1082–1106 µs/req 几乎相同，
差值 2–4 %。**即 CGO 进出边界不是瓶颈**，这一结论与常见直觉相反，已用实测证伪。

---

## 6. 未验证 / 待验证

* **待验证**：共享库（`-buildmode=c-shared`）内 996 µs/req 与同仓库代码编译成普通 Go
  可执行文件时 537 µs/req 的差异来源。两者运行**同一套** `executeRequestFromConfig`，
  且 `go test -bench` 直接跑该函数得到 597–843 µs/op，落在两者之间，因此差异不出在
  代码路径上。已排除：GOMAXPROCS（8）、`catch_panics`、`force_http1`、
  `random_tls_extension_order`、`without_cookie_jar`（A/B 全部落在噪声带内）。
  可能方向：动态链接下的 PLT/TLS 访问、ASLR 导致的跨页分布。
  **没有做进一步验证，因此不据此给出任何"优化已生效"的结论。**
* **待验证**：HTTP/2、HTTP/3 专项基准。本地 origin（`benchmarks/server`）只讲 HTTP/1.1，
  没有可重复的 h2/h3 测试服务；对公网目标做基准不具备可重复性，故**未测**。
* **未测**：Windows / macOS / ARM 平台上的任何数字。本次只在 `linux/amd64` 实测。
