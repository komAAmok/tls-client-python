# 性能文档索引 · Performance Docs

本目录记录 `tls-client-python` 的性能审计与优化结果。**每一条结论都对应真实代码位置或
真实测量**；未能验证的内容显式标记为"未测试 / 待验证"。

| 文档 | 内容 |
| --- | --- |
| [`architecture_review.md`](architecture_review.md) | 目录归属、真实调用链、连接池、原生构建、已实测瓶颈 |
| [`bottleneck_analysis.md`](bottleneck_analysis.md) | 逐层成本拆分、异步阻塞定位、被否决的方案、未解决问题 |
| [`optimization_results.md`](optimization_results.md) | 每一项改动的证据、实现、A/B 数据、风险；含两处**已回退**的负结果 |
| [`baseline.md`](baseline.md) | 采集条件、原始数据文件、复现步骤、负载警告 |
| [`memory_analysis.md`](memory_analysis.md) | 跨语言内存所有权、实测 RSS / tracemalloc、Go 堆为何未测 |
| [`binary_size_analysis.md`](binary_size_analysis.md) | ELF 段构成、12 平台产物、可复现性验证、为何没有体积产出 |
| [`final_report.md`](final_report.md) | 汇总：问题表、前后对比、文件清单、跨平台状态、最终建议 |

## 一句话结论

* **有效**：大响应延迟解码（逐样本穿插 A/B 两次独立运行：256 KiB −19…−30 %，
  1 MiB −40…−47 %，10 MiB −61…−64 %，峰值 RSS −12.2 %）；
  取消的异步请求不再解包（100×1 MiB 快 1.7–1.9 倍）。
  小响应体（≤64 KiB）**无可测收益**，两次测量符号不一致。
* **无效并已回退**：异步编组线程池（−19…−45 %）、netrc 查询缓存（净负收益）。
* **未解决**：1 MiB 响应解包仍阻塞事件循环；`c-shared` 与普通二进制约 1.8× 的
  引擎差异**原因未定位**；无 h2/h3 本地基准；无跨平台验证。
* **体积**：无优化产出，且不声称有。仓库内 linux/amd64 产物 14,095,240 → 14,102,944 字节
  的变化来自 CI 重建，与本次改动无关。
* **复核**：`final_report.md` §3.5 记录了推送后对三项说法的逐条查实，
  其中"远程二进制已验证"和"新二进制上性能已确认"两项**原有说法不完整/方法不合格，已推翻并回改**。

## 基准怎么跑

```bash
go build -o /tmp/benchserver ./benchmarks/server
.venv/bin/python benchmarks/harness.py --list
.venv/bin/python benchmarks/harness.py --all --json benchmarks/results/final.json
```

**重要**：这台开发机的 `load average` 常在 2.5–9.9 之间波动（浏览器占用一个核），
单次前后对比不可信。需要判定优化是否有效时，必须用交替 A/B：

粗粒度（每轮各起一个新解释器，适用于负载平稳的机器）：

```bash
.venv/bin/python benchmarks/ab.py --scenario body-size --rounds 3 \
    --a /path/to/baseline-tree --b /path/to/candidate-tree
```

逐样本穿插（本机负载波动大时必须用这个，结论更稳且更少低估）：

```bash
.venv/bin/python benchmarks/interleaved_ab.py \
    --a /path/to/baseline-tree --b /path/to/candidate-tree \
    --sizes 262144 1048576 10485760 --rounds 5 --per-round 8
```
