# 优化方案与实施记录 · Optimization Plan & Results

本次只实施了**两处**有实测证据支持的改动，另外**明确回退了两处**无效改动。
功能校验：全部 274 项 Python 测试在每次改动后都跑过，最终状态 `OK (skipped=1)`。

> 遥测口径说明：本机负载在 2.5–9.9 波动，因此下表所有"变化"都来自
> `benchmarks/ab.py` 的**交替 A/B**（A/B/A/B…，3–5 轮，取比值中位数）。
> 单次独立运行的前后对比被判定为不可信，已弃用。

---

## 1. P1 — 响应体延迟解码（已实施）

### 现状与证据

`tls_client/_core.py:2146` 的 `_unpack_c_response` 无条件解码整个响应体：

```python
text = body_bytes.decode(encoding)          # 旧实现
```

而 `tls_client/adapters.py:243` 只使用 `native.content`，**从不读取 `native.text`**
（`grep -n "native\.text" tls_client/*.py` 无结果）。也就是说，每个请求都付出了一次
完整解码的成本，结果没人用。

实测解码成本：

| 响应体 | `bytes.decode("utf-8")` |
| --- | --- |
| 64 KiB | 3.3 µs |
| 1 MiB | 53 µs |
| 10 MiB | **1.15 ms** |

10 MiB 的解码（1.15 ms + 目标字符串分配）比整个往返（约 33 ms 的旧实现里占 3 %，
但它是**持 GIL 的纯 CPU**，在并发下直接压缩吞吐）。

### 改动

* `Response.__init__` 的 `text` 参数保持签名不变，但允许 `None` 表示"尚未解码"。
* `Response.text`：首次访问时调用新增的 `_decode_body(content, encoding)` 并缓存。
* `_unpack_c_response` 不再解码，传 `text=None`。
* `Response.json()` 改读 `self.text`（而不是 `self._text`）。

`_decode_body` 是**唯一**解码实现，语义与旧代码逐字一致（同样的编码解析、
同样的 `UnicodeDecodeError`/`LookupError` → UTF-8 `replace` 回退），
因此惰性路径不可能与旧路径产生不同结果。

兼容性：`Response.text` 的返回类型、值、异常行为不变；`response.text` 仍然可用；
`json()` 行为不变。`None` 本来就是合法入参（会走上面那条 `_text` 分支），
所以这不是"新增一个模式"，而是"把同一个模式改成按需执行"。

### 验证

第一次用的是 `benchmarks/ab.py`（每轮各起一个全新解释器，两树相隔数十秒）。
复核时发现这个粒度**不够**：本机负载在轮次之间会漂移，逐轮样本跨度极大
（A 侧 1 MiB 一轮 4.6 ms、下一轮 16.7 ms），据此得出的数值偏保守且不稳定。

改用**逐样本穿插**协议重测，工具已入库为 `benchmarks/interleaved_ab.py`
（+ `benchmarks/_ab_child.py`）：同一 size 下 A/B 交替执行，每轮换先后顺序，
5 轮 × 8 样本 = 各 40 个样本，取中位数；两棵**代码树共用同一份 CI 二进制**，
唯一变量就是 perf 提交。

```bash
python benchmarks/interleaved_ab.py --a /path/to/baseline-tree --b . \\
    --sizes 262144 1048576 10485760 --rounds 5 --per-round 8
```

第三次独立确认（入库工具实跑，1 MiB，仅 8 样本）：`5.942 → 4.370 ms`（−26.5 %），
方向与前两次一致。

两次独立运行结果：

| 响应体 | 前 (ms) | 后 (ms) | 变化 | 前 (ms) | 后 (ms) | 变化 |
| --- | --- | --- | --- | --- | --- | --- |
| 256 KiB | 3.396 | 2.745 | **−19.2 %** | 2.929 | 2.039 | **−30.4 %** |
| 1 MiB | 7.063 | 4.272 | **−39.5 %** | 5.941 | 3.149 | **−47.0 %** |
| 10 MiB | 51.775 | 20.344 | **−60.7 %** | 53.078 | 19.178 | **−63.9 %** |

最小值同向（10 MiB：18.682→15.103、17.974→14.570 ms），说明不是靠平滑掉尖峰得到的。

**结论修正**：真实收益比初版记录的（−16.7 / −26.0 / −31.3 %）更大，
初版是测量协议偏弱导致的**低估**，不是优化变强了。

小响应（1 KiB / 4 KiB / 64 KiB）用同一协议两次测量：

```
run1  +11.9 %   −2.9 %   +2.4 %
run2   +1.0 %   +1.7 %  −17.0 %
```

两次符号不一致，**落在噪声内，不宣称小响应有任何收益**。这与机理相符：
1–64 KiB 的解码本身只有 0.03–3 µs，省掉它也测不出来。

10 MiB 单次延迟（`big-body-latency`，非交替，仅供参考）：
`p50 32.4 ms → 20.9 ms`，`10.5 MB/s → 477.6 MB/s`。

峰值 RSS：10 MiB 场景 `82,836 KB → 72,716 KB`（−12.2 %，来自较粗粒度的
`benchmarks/ab.py` 3 轮，峰值 RSS 对负载不敏感，未用新协议复测），
因为不再同时持有 `bytes` 和 `str` 两份。

### 风险

* 若调用方在 `Response` 上做了 `del response.content` 之后再读 `.text`，
  旧实现能返回已缓存的字符串，新实现会因为 `_content` 消失而在解码时抛
  `AttributeError`。这是极端用法，且 `content` 是只读属性（`__slots__` 里是
  `_content`），常规路径不可达。
* 首次访问 `.text` 的延迟从"构造时"移到"访问时"。对一次性的
  `resp.text` 用法总耗时不变；对从不读 `.text` 的用法规避了全部成本。

---

## 2. P1 — 取消的异步请求不再解包（已实施）

### 现状与证据

`_resolve_async_response` 在事件循环线程上解包 C 响应。取消语义是：
`future.cancel()` 之后 Go 侧的 goroutine **无法中止**（已经在跑），响应仍会回来，
回调仍会 `call_soon_threadsafe`，然后**照样整份复制响应体**——为了一个没人能观察到的结果。

1 MiB 响应下，`ffi.buffer(...)[:]` 实测 2.24 ms，这段全部落在事件循环上。

### 改动

* `_resolve_async_response` 开头 `if future.done(): return`（C 内存仍由 `ffi.gc` 释放）。
* 回调里在 `call_soon_threadsafe` 之前再判一次 `future.done()`，直接跳过 loop 往返，
  并保留 `ffi.gc(raw_gc, lib.FreeResponse)` 绑定以确保 `FreeResponse` 仍会执行。

不改变任何可观察语义：已取消的 Future 本来就拿不到结果，唯一变化是少做一次
没人要的拷贝。

### 验证

100 × 1 MiB 并发 `gather`（交替 A/B，3 轮，同一脚本、同一 timeline）：

| 轮次 | 前 | 后 |
| --- | --- | --- |
| 1 | 0.661 s | 0.401 s |
| 2 | 0.749 s | 0.384 s |
| 3 | 0.864 s | 0.440 s |

稳定快 **1.7–1.9 倍**。取消/超时行为本身由
`benchmarks/harness.py --scenario async-cancel-timeout` 与
`python_tests/test_concurrency.py` 覆盖，A/B 两树结果一致（`cancelled=1`）。

---

## 3. P2 — 代理环境变量重复扫描（已实施，收益小但确定）

`tls_client/utils.py:646` `get_environ_proxies` → `should_bypass_proxies` →
`proxy_bypass(hostname)`。在 POSIX 上 `proxy_bypass_environment()` 会**重新**
遍历整个 `os.environ`（`getproxies_environment()`），而同一请求里
`getproxies()` 刚刚做过一次同样的扫描。

改动：POSIX 分支改为 `proxy_bypass(hostname, getproxies())`，复用同一份映射。
Windows 保持 `proxy_bypass(hostname)`（那里走注册表）。
语义不变：`proxy_bypass_environment` 只是从映射里取 `no_proxy`。

验证：`should_bypass_proxies` 17.5 µs → 15.2 µs；运行时修改/`删除` `HTTP_PROXY`、
设置 `NO_PROXY` 的行为逐项验证通过；`test_requests_behaviour.py` 全绿。

**注意**：这条在总时间里的占比极小（约 2 µs/请求），列出来是为了诚实记录，
不宣称它带来可测量的吞吐提升。

---

## 4. 明确回退的两处（记录为负结果）

### 4.1 编组搬到线程池 — 回退

见 `bottleneck_analysis.md` §2.2：交替 A/B 3 轮显示各并发度下**下降 19–45 %**。
原因是 GIL：纯 Python 编组在线程池里没有并行，只多了排队与往返。
**已完整回退。**

### 4.2 netrc 查询缓存 — 回退

曾按 `(host, netrc 文件 stat)` 缓存 `get_netrc_auth`。实测缓存键本身要两次
`os.stat`，合计 **25.7 µs**，比不缓存的 **24.2 µs** 还贵；而省掉的是
`import netrc`（已被 `sys.modules` 缓存）。**净负收益，已回退。**
（尝试过用"文件曾不存在就跳过 stat"来规避，但那会在文件随后出现时漏掉凭据，
属于用正确性换 12 µs，拒绝。）

---

## 5. 二进制体积

**本次没有体积产出，也不声称有。** 详见 `binary_size_analysis.md`：
现有构建已经 `-s -w -buildid= -trimpath`，`.gopclntab`（3.99 MB）是唯一的大块，
删掉会让 panic 栈失去函数名，属于功能退化，拒绝。
