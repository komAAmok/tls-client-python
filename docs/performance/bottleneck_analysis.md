# 瓶颈分析 · Bottleneck Analysis

所有数字都来自本机实测（8 核 i7-14650HX / Python 3.12.3 / Go 1.27.4 / gcc 13.3.0）。
脚本与原始 JSON 见 `benchmarks/` 与 `benchmarks/results/`。

测量方法上有一个必须说明的坑：**单次 before/after 对比在本机不可信**。
这台机器同时跑着浏览器（渲染进程常驻一个核），`uptime` 在 2.5–9.9 之间波动，
同一份代码两次测量可以差 60 %。因此所有结论都来自
`benchmarks/ab.py` 的**交替 A/B**（A/B/A/B…，取每轮比值的中位数），
而不是两次独立运行。早期用非交替方式得到的"性能提升 118 %""下降 39 %"等结果
已作废，不作为结论。

---

## 1. 单请求成本拆分（同步，1 KiB 响应，单线程）

用三种互相独立的方法交叉验证：

| 方法 | 结果 |
| --- | --- |
| 在 Python 里给 `_lib.ExecuteRequest` 计时而外其余照常 | 全程 1318 µs，其中 `ExecuteRequest` **916 µs（69.5 %）** |
| Go 侧插桩（`client.Do` + 读体 + 打包分段计时） | `client.Do` 595 µs、读体打包 200 µs、CGO 出入 46 µs |
| 把 3000 次请求放进一次 CGO（`BenchInline`） | 996–1089 µs/req，与逐请求 CGO 的 1082–1106 µs/req 相差 **2–4 %** |

结论：**CGO 边界不是瓶颈，Go 引擎本身占大头，第二块是 Python 侧编组。**

### 1.1 Python 侧各阶段（wall-clock，单次调用）

```
Session.get (full)                   1183 µs
  merge_environment_settings           27.8 µs
  _prepare_request_compat              17.7 µs
  _build_headers(13 hdr)               10.1 µs
  _snapshot_selected_defaults           6.2 µs
  _compute_cache_key_hash               4.9 µs
  _build_headers(2 hdr)                 2.1 µs
  _build_string_array(4)                1.7 µs
  _normalize_int_fields                 1.6 µs
  _merge_default_headers               1.4 µs
Response() ctor                         0.26 µs
```

`Session.get` 减去 `ExecuteRequest` 后剩下的约 400 µs，经"把 `ExecuteRequest`
替换成直接返回既有响应"的实验确认：**纯 Python 每请求 212.8 µs**
（`prepare_request` 占 190 µs 以上）。其余差额来自 CFFI 对象创建与 GC。

### 1.2 响应体大小的影响

Go 侧插桩（原库 + 计时补丁，`/tmp/build/instr.so`，不改仓库）：

| 响应体 | `client.Do` | 读体 | 打包 | CGO+Python |
| --- | --- | --- | --- | --- |
| 0 B | 735 µs | 6 µs | 7 µs | 85 µs |
| 1 KiB | 778 µs | 254 µs | 7 µs | 97 µs |
| 16 KiB | 689 µs | 252 µs | 7 µs | 86 µs |
| 1 MiB | 894 µs | 1421 µs | 7 µs | 2153 µs |

小响应是固定成本主导；1 MiB 时读体（一次 C 堆 `malloc` + 一次 `io.ReadFull`）
和 Python 侧 `ffi.buffer(...)[:]` 的复制开始成为主要成本。

---

## 2. 异步路径

### 2.1 事件循环被 `_unpack_c_response` 阻塞

`_resolve_async_response`（`_core.py`，异步回调）**在事件循环线程上**执行
`ffi.buffer(...)[:]` + 头表解析。实测（32 并发 × 10 轮，1 MiB 响应）：

```
基线                 wall=0.226 s  heartbeat lag p50=15.95 ms  p95=62.88 ms
把 unpack 打桩       wall=0.182 s  heartbeat lag p50=15.50 ms  p95=18.13 ms
```

即 1 MiB 响应的解包会把 1 ms 心跳推迟到 60 ms 级。**这是真实的 P0 级问题**，
但它的根治需要把解包搬离事件循环，而 GIL 决定了搬到线程池并不会有并行收益
（见下），因此本次只修掉了"请求已取消却仍然解包"这一确定浪费。

### 2.2 线程池方案被实测否决

曾实现"把编组搬到有界线程池"的方案（`_marshal_executor` + `run_in_executor`），
交替 A/B 3 轮结果：

| 并发 | 基线 rps | 线程池 rps | 变化 |
| --- | --- | --- | --- |
| 1 | 690 | 419 | −39 % |
| 8 | 1219 | 694 | −43 % |
| 32 | 1141 | 793 | −31 % |
| 128 | 1167 | 818 | −30 % |

**结论：该方案让异步全面变慢 3 成**，原因是编组是 CPU-bound 纯 Python，
线程池只增加了切换与 `run_in_executor` 的往返，没有带来任何并行（GIL），
同时把原本"编组 + Go 并行"的重叠关系变成了"先排队再编组"。
已完整回退，代码中不留残余。

---

## 3. 同步并发上限

CFFI **ABI mode 的调用会释放 GIL**（实测：4 线程 2753 rps vs 1 线程 948 rps，
`ctypes` 对照组 2748 rps，两者一致）。因此真正的上限是**每请求持 GIL 的
Python 工作量（约 210 µs）**，而不是 CGO 边界。

绕开 Python 直接测 CGO 的线程扩展性（`RequestOptions` 手工构造）：

| 线程 | rps | p50 |
| --- | --- | --- |
| 1 | 1196 | 803 µs |
| 2 | 2409 | 789 µs |
| 4 | 3447 | 1003 µs |
| 8 | 4333 | 1509 µs |
| 16 | 3809 | 3322 µs |

即"引擎 + C ABI"在 8 线程下能到 4333 rps，而完整 requests 门面只有约 1450 rps
（`sync-threads shared_16`）。**约 3 倍差距全部来自 Python 门面**。

---

## 4. 二进制体积

```
14,095,240  tls-client-linux-amd64.so
  .text         5,718,204   Go 代码
  .gopclntab    3,989,392   Go 符号表（panic 栈/反射需要）
  .data.rel.ro  1,236,696
  .rodata         479,360
```

构建参数已含 `-s -w -buildid= -trimpath -buildvcs=false`，并已验证
**同一台机器重建产物与仓库内产物逐字节相同**（可复现）。
在"不删功能"的前提下，本机没有找到可安全再削的部分：
`.gopclntab` 是最大的可削块，但删除会让 panic 栈丢函数名（功能退化，已拒绝）；
`profile` tag 已经默认关闭。**因此本次没有体积优化产出，也不声称有。**

---

## 5. 已确认但本次未修的问题

| 问题 | 证据 | 为什么没修 |
| --- | --- | --- |
| 1 MiB 响应解包阻塞事件循环 | 上文心跳 62.88 ms | 根治需要在不持 GIL 的前提下解包，涉及新 ABI（native handle + 分块读取），超出本次可验证范围 |
| 引擎自身 c-shared 与普通二进制的差异 | 996 µs vs 537 µs | **待验证**，原因未定位，不据此下结论 |
| HTTP/2、HTTP/3 没有本地可重复基准 | — | 本地 origin 只讲 HTTP/1.1；不做不可复现的互联网基准 |
| `_prepare_request` 仍约 190 µs | `PreparedRequest.prepare` 单独实测 48 µs + 上层开销 | 它是 requests 兼容语义的载体，改写风险大、收益需单独 A/B 验证 |
