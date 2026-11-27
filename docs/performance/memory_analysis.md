# 内存分析 · Memory Analysis

## 1. 内存所有权（从代码确认）

| 内存 | 分配方 | 释放方 | 生命周期 |
| --- | --- | --- | --- |
| `*C.ResponseResult` 结构体 | Go `C.malloc`（`main.go:1727`） | `FreeResponse`（`main.go:2073`） | Python 侧用 `ffi.gc(...)` 绑定（`_core.py:3786`） |
| 响应头 + Cookie 字符串 | **单次 arena** `C.malloc`（`packResponseArena`，`main.go:1969`） | `FreeResponse` 里一次 `C.free` | 同上 |
| 响应体 | `readBodyToCHeap` 直接 `C.malloc` 进 C 堆（`main.go:517`） | `FreeResponse` | 同上 |
| `RequestOptions` 及其字符串 | Python `ffi.new` | Python GC（`keep_alive` 列表） | sync：调用期间；async：到回调触发 |
| 请求体 | Python `bytes`，`ffi.from_buffer` 零拷贝借用 | Python GC | sync：阻塞期间；async：`C.GoBytes` 深拷贝后即可释放 |
| async 响应 | Go `C.malloc` | 回调里 `ffi.gc` → `_resolve_async_response` 结束后释放 | 到 Future 完成 |

**所有权是明确的**：Go 分配的一律 `C.malloc` + `FreeResponse` 释放；
Python 分配的一律由 Python GC 释放。跨语言指针没有互相 free 的情况。

### 已核对的细节

* `FreeResponse` 有 arena 快路径与旧的逐字符串慢路径两条分支，
  arena 路径下 `cookies` 与 `response_headers` 指向同一块内存，释放后显式置 `nil`
  避免二次释放（`main.go:2079-2092`）。
* async 回调的异常兜底里用 `ffi.release(raw_gc)` 先解绑再手动 `FreeResponse`，
  避免 `ffi.gc` 之后重复释放（`_core.py` 回调 `except` 分支）。
* async 的"僵尸超时"（`_on_zombie_timeout`）只丢弃 `keep_alive`，
  文档里写明这是安全的——因为 `RequestAsync` 在返回前已 `C.GoBytes` 深拷贝。
  这一条我对照 `main.go:688-695` 核过：async 分支确实是 `copyBody=true`。

## 2. 实测内存

### 2.1 稳态 RSS（`memory-idle-and-loaded`）

| 状态 | RSS |
| --- | --- |
| 空闲（300 次请求后 GC） | 约 105 MB |
| 加载中（再 500 次 4 KiB） | 约 105 MB |

两者相同，说明 4 KiB 量级没有随请求数增长的留存。Python 侧
`tracemalloc` 在 500 次请求后的净增长为 **27.3 KiB**（全部来自
`api.py` 的模块级结构），**没有 per-request 泄漏**。

### 2.2 10 MiB 响应

优化前后（交替 A/B，3 轮中位数）：

| 指标 | 前 | 后 |
| --- | --- | --- |
| peak RSS | 82,836 KB | 72,716 KB |
| `rss_delta` | 16 KB | 164 KB |

峰值下降 12.2 %，机理是惰性解码后不再同时持有 `bytes` 与 `str` 两份 10 MiB。

> `rss_delta` 在两个方向上都很小且抖动大（同一格子里 16 KB vs 164 KB），
> 因为它测的是"GC 后"的差值，而大对象此时已经被回收。**以 peak RSS 为准。**

### 2.3 Python allocator

`tracemalloc` 峰值：500 次 4 KiB 请求期间 **288 KiB**。
这在预期内：每请求分配的临时 CFFI 对象在调用结束时即释放，
Python 层不留长生命周期对象。

## 3. Go 堆

**未能测量。** `_core.runtime_stats()` 依赖 `profile` build tag
（`introspect_profile.go`），而仓库内的发布库是**不带** `profile` 的，
调用会抛 `RuntimeError`（这是刻意设计："失败得响亮好过返回 0 被当成没有泄漏"）。

本次没有为了拿数字而重建一个带 `profile` 的发布库，因为那测到的就不是发布产物的行为了。
**`HeapAlloc` / `HeapInuse` / `NumGoroutine` 一律标记为未测。**

需要这些数字时：

```bash
TLS_CLIENT_BUILD_TAGS=profile,netgo,osusergo \
  .venv/bin/python cffi_binding/build_binding.py --lib
.venv/bin/python -c "import tls_client._core as c; print(c.runtime_stats())"
```

## 4. 结论

* 未发现泄漏、重复 free、跨语言所有权错误。
* 同步/异步小响应下内存稳态，无随请求数增长。
* 大响应峰值下降 12.2 %（惰性解码的副产物，非独立优化）。
* Go 侧堆指标未测，不做结论。
