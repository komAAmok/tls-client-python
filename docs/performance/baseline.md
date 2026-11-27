# 基线数据 · Baseline

## 采集条件（可复现所必需）

| 项 | 值 |
| --- | --- |
| 仓库 | `tls-client-python` |
| HEAD | `cd0bd44` `fix(ci): clear the lint gate that blocked wheel builds and PyPI upload` |
| 平台 | `Linux-7.0.0-38-generic-x86_64-with-glibc2.39` |
| CPU | Intel Core i7-14650HX，8 逻辑核（`nproc` = 8） |
| Python | 3.12.3（`.venv`） |
| Go | go1.27.4 linux/amd64 |
| gcc | 13.3.0 |
| 共享库 | `tls_client/bin/tls-client-linux-amd64.so`，14,095,240 B，md5 `5575630d…` |
| origin | `benchmarks/server`（本地 Go 服务，HTTP/1.1 keep-alive） |

**负载警告**：采集期间本机同时运行浏览器（渲染进程常驻一个核），
`load average` 在 2.5–9.9 间波动。因此：

* 单次运行的前后对比**不可信**，本目录中所有 A/B 结论均来自
  `benchmarks/ab.py` 的交替 A/B（A/B/A/B…）取比值中位数。
* 绝对 rps 数字只用于同一次运行内部的相对比较，**不可跨时间横向对比**。

## 原始数据文件

| 文件 | 内容 |
| --- | --- |
| `benchmarks/results/baseline.json` | 优化前全量场景 |
| `benchmarks/results/final.json` | 优化后全量场景 |
| `benchmarks/results/ab-lazytext-bodysize.json` | 惰性解码 · 响应体大小 A/B（3 轮） |
| `benchmarks/results/ab-sync-sequential.json` | 同步顺序请求 A/B（5 轮） |
| `benchmarks/results/ab-async-gather.json` | 异步 gather A/B（3 轮，线程池方案，已回退） |
| `benchmarks/results/ab-async-cancel.json` | 取消/超时行为 A/B（3 轮，行为等价性） |

## 基准工程

```
benchmarks/
  harness.py        场景化基准（12 个场景，支持 --json 落盘）
  ab.py             交替 A/B 运行器（抵消主机漂移）
  server/main.go    本地 Go origin（HTTP/1.1 keep-alive，远高于客户端）
  go/engine_bench/  绕开 CGO 直接压 Go 引擎
  results/          原始 JSON
```

一条命令跑完：

```bash
go build -o /tmp/benchserver ./benchmarks/server
.venv/bin/python benchmarks/harness.py --all --json benchmarks/results/final.json
.venv/bin/python benchmarks/harness.py --list     # 查看可用场景
```

交替 A/B：

```bash
.venv/bin/python benchmarks/ab.py --scenario body-size --rounds 3 \
    --a /path/to/baseline-tree --b /path/to/candidate-tree \
    --json benchmarks/results/ab.json
```

两个树必须是**已 checkout 且已放好共享库**的完整工作树；脚本不负责构建。

## 基线关键读数（优化前，`baseline.json`）

| 场景 | 读数 |
| --- | --- |
| `sync-sequential` 1 KiB | 758.9 rps，p50 1.260 ms，p95 1.706 ms |
| `sync-threads shared_16` | 1483.8 rps |
| `async-gather c16` | 1699.6 rps，p95 9.376 ms |
| `async-gather c256` | 1770.8 rps，p95 135.27 ms |
| `raw-ffi-floor`（仅 ExecuteRequest） | 1224.4 rps |
| `big-body-latency` 10 MiB | p50 32.395 ms |
| `async-loop-lag`（32×1 MiB） | p95 102.2 ms，max 849.9 ms |
| `memory` idle / loaded RSS | 105,684 KB / 105,684 KB |

> `raw-ffi-floor` 1224 rps 与 `sync-sequential` 759 rps 的差（约 465 rps）
> 就是 requests 兼容门面的成本。这个差值是后续所有 Python 侧优化的靶子。

## 复现检查清单

1. `go version` ≥ 1.27，`python3 -V` = 3.12
2. `tls_client/bin/tls-client-linux-amd64.so` 的 md5 = `5575630d95c865f91e70259165974601`
   （若不同，说明本地重建过，数字不可比）
3. 确认 `/tmp/benchserver` 已构建
4. 先跑 `python benchmarks/harness.py --scenario sync-sequential` 两次，
   若两次 rps 相差 > 15 %，说明主机负载不稳，此时只能相信 `ab.py` 的结果
