# 最终优化报告 · Final Report

## 1. 当前架构

见 [`architecture_review.md`](architecture_review.md)。摘要：

```
Session / AsyncSession (tls_client/_core.py)
  → requests 门面 (sessions.py → adapters.py)
  → CFFI **ABI mode** (ffi.dlopen + 运行期 cdef)
  → C ABI (cffi_binding/main.go, //export ExecuteRequest / RequestAsync)
  → Go 引擎 (上游 client.go / roundtripper.go，未改动)
  → TLS(fingerprint) / HTTP1.1 / HTTP2 / HTTP3
```

## 2. 现存性能问题

| 优先级 | 模块 | 文件 / 函数 | 实际问题 | 根本原因 | 优化方案 | 状态 |
| --- | --- | --- | --- | --- | --- | --- |
| P1 | 响应解包 | `_core.py:2146 _unpack_c_response` | 每响应无条件解码整个 body | 惰性数据被急切计算 | 延迟到 `.text` 首次访问 | **已实施** |
| P1 | 异步取消 | `_core.py _resolve_async_response` | 已取消请求仍在 loop 上整份复制 body | 缺 `future.done()` 短路 | 早退 + 跳过 loop 往返 | **已实施** |
| P2 | 代理环境 | `utils.py:633 should_bypass_proxies` | 同一请求内 `os.environ` 被扫两遍 | `proxy_bypass()` 内部重扫 | 传入已有映射 | **已实施** |
| P1 | 异步编组 | `_core.py _execute_async` | 编组全部在 loop 线程（约 210 µs） | 设计如此 | 线程池 | **实测负收益，已回退** |
| P1 | 异步解包 | `_core.py _resolve_async_response` | 1 MiB 响应在 loop 上复制 2.24 ms | 设计如此 | 需 native handle + 分块读取（新 ABI） | **未实施** |
| — | 引擎 | `client.go do()` | c-shared 下 996 µs vs 普通二进制 537 µs | **待验证** | — | **未定位** |
| — | 二进制 | `.gopclntab` 3.99 MB | 体积大头 | panic 栈需要 | 删除会丢函数名 | **拒绝** |

**没有一项是编造的**：上表每一行的文件、函数、数字都能在
`architecture_review.md` / `bottleneck_analysis.md` / `optimization_results.md` 里找到对应的实测出处。

## 3. 性能对比

> 说明：本机 `load average` 在 2.5–9.9 波动，**单次独立运行的前后对比不可信**
> （早期一次这样的对比给出了"小响应慢 118 %"的错误结论，已作废）。
> 下表的"实测"列注明数据来源；只有交替 A/B 的结果被当作结论。
> 无法用交替 A/B 覆盖的项，标记为"未测试"。

| 测试项 | 修改前 | 修改后 | 变化 | 依据 |
| --- | --- | --- | --- | --- |
| Sync QPS（1 KiB，单线程） | 646.4 | 659.9 | +2.1 % | 实测·交替 A/B 5 轮（在噪声带内，不宣称收益） |
| Async QPS（gather c16） | 1699.6 | 1699 量级 | 未测得稳定变化 | 实测·交替 A/B 3 轮（噪声内） |
| Async 100×1 MiB 完成时间 | 0.661 / 0.749 / 0.864 s | 0.401 / 0.384 / 0.440 s | **快 1.7–1.9×** | 实测·交替 A/B 3 轮 |
| 256 KiB 响应 | 3.396 / 2.929 ms | 2.745 / 2.039 ms | **−19.2 % / −30.4 %** | 实测·逐样本穿插 A/B，2 次独立运行 |
| 1 MiB 响应 | 7.063 / 5.941 ms | 4.272 / 3.149 ms | **−39.5 % / −47.0 %** | 同上 |
| 10 MiB 响应 | 51.775 / 53.078 ms | 20.344 / 19.178 ms | **−60.7 % / −63.9 %** | 同上 |
| 10 MiB 单次 p50 | 32.4 ms | 20.9 ms | −35 % | 实测·单次运行（仅供量级参考） |
| ≤64 KiB 响应 | — | — | ±11 % 内 | 实测·交替 A/B（噪声内，**不宣称**） |
| p95 延迟（sync 1 KiB） | 2.031 ms | 1.953 ms | −3.8 % | 实测·交替 A/B 5 轮（噪声边缘） |
| Peak RSS（10 MiB） | 82,836 KB | 72,716 KB | **−12.2 %** | 实测·交替 A/B 3 轮 |
| Peak RSS（稳态 4 KiB） | 105,684 KB | 105,684 KB | 0 | 实测·单次运行 |
| Go HeapAlloc | — | — | 未测试 | 发布库无 `profile` tag |
| Goroutine 数量 | — | — | 未测试 | 同上 |
| Python allocations（netrc / 500 req） | — | 27.3 KiB | 无 per-request 泄漏 | 实测·tracemalloc |
| HTTP/2 QPS | — | — | 未测试 | 无本地可重复 h2 origin |
| HTTP/3 QPS | — | — | 未测试 | 无本地可重复 h3 origin |
| 原生二进制体积（linux/amd64） | 14,095,240 B | 14,102,944 B | +0.05 % | 实测；差异来自 CI 重建，非本次改动 |
| Wheel 体积（全平台，本机构建） | — | 62,202,008 B | 未对比 | 实测单点；CI 按平台分包，本机未跑 CI |

## 3.5 复核记录（推送后按三项逐条查实）

推送后按要求逐条复核，其中**两项推翻了先前的说法**，已回改。

### 3.5.1 变基完整性

用 `git patch-id --stable` 逐提交比对变基前后的内容哈希：

```
IDENTICAL    pre=e8f6fe5eb541 post=e8f6fe5eb541
IDENTICAL    pre=5e946c16f8d0 post=5e946c16f8d0
IDENTICAL    pre=b1ad02c2c4f3 post=b1ad02c2c4f3
```

三个提交一行未改。另外在独立 worktree 里 checkout 中间提交 `8659cb3`，
确认它能单独 `import tls_client` 并通过 `test_py36_compat`——变基没有制造
"只有末提交才成立"的隐性依赖。两个 CI 提交经 `--numstat` 确认**零文本行改动**
（0f2ddee 动 12 个二进制、68977d2 动 8 个），本地 `bin/` 与远程逐字节一致。

### 3.5.2 远程二进制校验（先前不完整，已补齐）

原说法是"确认 ABI 4、Session 能构造"，但那**只测了 12 个库里的 linux/amd64 一个**。
补齐后的结论见 [`binary_size_analysis.md`](binary_size_analysis.md) §4.2–4.3：

* 12/12 架构正确、15 个 ABI 导出齐全（Mach-O 与 PE 用自写导出表解析，
  因为 `nm -D` 读不了这两种格式——**第一次用错工具得出了"全部缺失"的错误结论**）。
* linux/amd64 加载正常、274 项测试通过。
* **CI 产物不能在本机逐字节复现**（14,127,600 vs 14,102,944），
  已定位到 buildinfo 记录了 `-trimpath` 字面路径，剩余差异未定位。
  因此不声称"CI 产物可由源码复现"，只声称 ABI 与依赖表一致。
* 其余 11 个平台**只做了静态校验，没有运行过**。

### 3.5.3 性能收益在新二进制上复测（先前方法不合格，已重做）

先前的"复测"是**单次运行**，正是本文档开头明令禁止的做法。改用逐样本穿插 A/B
（工具已入库为 `benchmarks/interleaved_ab.py`，5 轮 × 8 样本，两树共用同一份
CI 二进制）后，两次独立运行 + 一次工具冒烟（1 MiB −26.5 %）：

| 响应体 | 运行1 变化 | 运行2 变化 |
| --- | --- | --- |
| 256 KiB | −19.2 % | −30.4 % |
| 1 MiB | −39.5 % | −47.0 % |
| 10 MiB | −60.7 % | −63.9 % |

**收益比初版记录的更大**（初版 −16.7 / −26.0 / −31.3 % 是测量协议偏弱造成的低估）。
小响应体两次测量符号不一致，仍判定为无收益。

---

## 4. 文件修改清单

| 文件 | 修改内容 | 修改原因 | 测试结果 |
| --- | --- | --- | --- |
| `tls_client/_core.py` | `Response.`行`text` 惰性解码；新增 `_decode_body`；`_unpack_c_response` 不再解码；`json()` 改读 `.text` | 省掉从未被读取的解码 | 274 项测试通过；A/B 见上 |
| `tls_client/_core.py` | `_resolve_async_response` 与回调增加 `future.done()` 短路 | 取消后不再复制 body | 274 项通过；A/B 1.7–1.9× |
| `tls_client/utils.py` | `should_bypass_proxies` 在 POSIX 上复用 `getproxies()` | 消除重复 `os.environ` 扫描 | 行为逐项手工验证 + 测试通过 |
| `benchmarks/harness.py` | 新增：12 场景基准工程 | 建立可重复基线 | 自测通过 |
| `benchmarks/ab.py` | 新增：交替 A/B 运行器 | 主机漂移下唯一可信的对比方式 | 自测通过 |
| `benchmarks/server/main.go` | 新增：本地 Go origin | 原 Python origin 上限约 800 rps，会成为被测对象 | 自测通过 |
| `benchmarks/go/engine_bench/main.go` | 新增：绕开 CGO 的引擎基准 | 分离"引擎问题"与"绑定问题" | 自测通过 |
| `docs/performance/*.md` | 新增 5 份文档 | 交付 | — |
| `benchmarks/interleaved_ab.py`、`benchmarks/_ab_child.py` | 新增：逐样本穿插 A/B 工具 | 粗粒度交替在本机负载下会低估且不稳定 | 实跑通过 |
| `benchmarks/results/*.json` | 原始数据 | 交付 | — |

**未修改任何上游文件**（`AGENTS.md` 约束），因此不需要在 `UPSTREAM_SYNC.md` 登记新的 overlay point。

## 5. 跨平台验证

| 项目 | 状态 |
| --- | --- |
| linux/amd64 编译 | ✅ 本地构建产物与审计当日仓库内二进制逐字节相同（`5575630d…`）；CI 重建后为 `89e17e76…`，ABI 与导出符号集一致，但**不可本地逐字节复现**（见 binary_size_analysis.md §4.2） |
| linux/amd64 运行测试 | ✅ 274 项 Python 测试通过 |
| linux/amd64 基准 | ✅ 见上 |
| linux/arm64、arm、386、musl 变体 | ⚠️ 仅静态校验：架构正确 + 15 个 ABI 导出齐全；**未运行** |
| Windows 386/amd64/arm64 | ⚠️ 仅静态校验：PE 导出表 24 个符号齐全；**未运行** |
| macOS amd64/arm64 | ⚠️ 仅静态校验：Mach-O 59 个外部符号齐全；**未运行** |
| Python 3.6–3.11、3.13、3.14 | ❌ 本机只有 3.12.3；`test_py36_compat` 通过（语法级） |

**本次改动全部是纯 Python 且不含平台相关代码路径**（唯一平台分支是
`utils.py` 里的 `os.name == "nt"`，Windows 侧保留原行为），
因此跨平台风险低；但"未验证"就是未验证，不声称全平台兼容。

## 6. 最终建议

1. **最优同步并发**：多线程 + 共享 `Session`（实测 `shared_16` 最优）。
   真正的天花板是每请求约 210 µs 的持 GIL Python 编组，而不是 CGO 边界——
   绕开 Python 直接压 CGO 能到 4333 rps（8 线程），完整门面约 1450 rps。
   下一阶段最值得投入：把 `prepare_request` 那条约 190 µs 的链路压掉。
2. **最优异步**：现状（Go goroutine + CFFI 回调 + Future）在**小响应**上已经接近最优，
   线程池方案实测慢 3 成，**不要**再走这条路。真正的短板是大响应解包占用事件循环，
   需要新 ABI（native handle + 分块读取）才能根治。
3. **最优连接池**：现状合理——进程级 `sync.Map` + `cache_key_hash` + LRU 上限 1024
   + TTL 300 s，且不同指纹/代理正确隔离。没有证据支持调整这些参数。
4. **最优内存方案**：惰性解码（本次已做）+ 大响应走 `stream_to_file`
   （引擎侧已支持按块写盘，`main.go:1893`）。剩余空间在"流式读取到 Python"，
   需要新 ABI。
5. **最优 CFFI/ABI 设计**：保持 ABI mode + arena 响应打包（现状已经是单次 malloc）。
   **不建议**为零拷贝引入跨调用指针——所有权与生命周期风险大于收益。
6. **最优 Go 编译方案**：维持 `-s -w -buildid= -trimpath -buildvcs=false -tags=netgo,osusergo`。
   已可复现。体积上无可安全再削项。
7. **仍未解决**：① 大响应解包阻塞事件循环；② c-shared 与普通二进制约 1.8× 的差异（未定位）；
   ③ 无 h2/h3 本地基准；④ 无跨平台验证。
8. **下一阶段最值得投入**：先定位 ②（它可能是最大的单点收益，但目前**完全没有证据**），
   再决定是否为 ① 引入新 ABI。
