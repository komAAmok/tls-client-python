# 二进制体积分析 · Binary Size Analysis

## 1. 实测数据

环境：linux/amd64，Go 1.27.4，仓库 HEAD `cd0bd44`，`tls-client/bin/tls-client-linux-amd64.so`。

```
14,095,240  tls_client/bin/tls-client-linux-amd64.so
   text     11,556,606   data  2,525,859   bss  33,996,824
```

ELF 段（`readelf -SW`）：

| 段 | 大小 | 说明 |
| --- | --- | --- |
| `.text` | 5,718,204 | Go 代码 |
| `.gopclntab` | 3,989,392 | Go 符号/行号表，panic 栈与反射依赖 |
| `.data.rel.ro` | 1,236,696 | 重定位只读数据（含 TLS profile 表） |
| `.rodata` | 479,360 | 只读常量 |
| `.rela.dyn` | 1,302,072 | 动态重定位 |

C 依赖只有 `libc.so.6` + `ld-linux`（`ldd`），没有多余动态库。

## 2. 各平台产物

```
tls-client-linux-amd64.so          14,095,240
tls-client-linux-amd64-musl.so     15,228,297
tls-client-linux-arm64.so          14,355,496
tls-client-linux-arm64-musl.so     14,359,945
tls-client-linux-arm.so            14,890,796
tls-client-linux-arm-musl.so       14,958,649
tls-client-linux-386.so            13,898,196
tls-client-darwin-amd64.dylib      12,682,976
tls-client-darwin-arm64.dylib      11,952,450
tls-client-windows-amd64.dll       13,065,728
tls-client-windows-arm64.dll       12,060,672
tls-client-windows-386.dll         12,442,112
合计                              163,990,557
```

Wheel（`python -m build --wheel`，本机构建）：

```
tls_client_python-1.18.1.1-py3-none-any.whl    62,202,008 字节
```

注意这是 **12 个平台库全打包**的 universal wheel。CI 的真实发布流程是按平台拆分
manylinux/musllinux/windows/macos wheel（见 `.github/workflows/build_workflow.yml`），
单个平台 wheel 只会带一个库。本机没有跑 CI，因此**不提供单平台 wheel 体积**。

## 3. 已有优化（在本仓库中已生效，非本次新增）

* `-ldflags="-s -w -buildid="`：剥离符号表与 DWARF，清空 build id。
* `-trimpath`、`-buildvcs=false`：去掉路径与 VCS 信息，同时保证可复现。
* `-tags=netgo,osusergo`：纯 Go 解析器，避免链接 NSS。
* `charset_lean.go`：用本地实现替代 `golang.org/x/net/html/charset`，
  按 `UPSTREAM_SYNC.md` 记录省下约 110 KB（14,095,224 → 13,984,760，−0.8 %）。
  当前产物 14,095,240 与该记录的基线差异来自后续 upstream 同步，不是回退。
* `profile` build tag：`runtime/pprof` + `runtime/debug`（约 230 KB）默认不编入。

## 4. 可复现性验证

```
$ (cd cffi_binding && go build -buildmode=c-shared -buildvcs=false -trimpath \
     -tags=netgo,osusergo -ldflags="-s -w -buildid=" -o /tmp/build/verify.so .)
$ md5sum /tmp/build/verify.so tls_client/bin/tls-client-linux-amd64.so
5575630d95c865f91e70259165974601  /tmp/build/verify.so
5575630d95c865f91e70259165974601  tls_client/bin/tls-client-linux-amd64.so
```

**逐字节相同**。这既是可复现构建的证据，也是"仓库里的产物确实来自当前源码"的证据。

## 5. 本次结论：没有体积产出

在"不删功能"的前提下，本机没有找到可以安全再削的部分：

| 候选 | 可省 | 为什么不做 |
| --- | --- | --- |
| `-ldflags "-s -w"` | 已在用 | — |
| 删除 `.gopclntab` | 约 3.99 MB | panic 栈会失去函数名、反射失效。属于功能退化，拒绝。 |
| `profile` tag 关闭 | 已在默认关闭 | — |
| UPX 等可执行压缩 | 视比例 | 会改变加载方式、影响启动与安全软件兼容；未做任何实测，因此**不建议、不采用**。 |
| 精简构建档位 | — | 需求明确禁止用"精简档"冒充完整档，且会引入能力差异；本次不引入。 |

因此：**完整功能构建的体积维持 14,095,240 字节（linux/amd64），本次未变。**
不满足"体积下降"的验收项，如实记录为未达成，而不是用别的口径凑数。

## 6. CFFI 扩展

本项目是 **CFFI ABI mode**（`ffi.dlopen` + 运行期 `ffi.cdef`），
不生成编译型 C 扩展模块，所以 wheel 里没有额外的 `.so`/`.pyd` 扩展产物，
只有上表列出的 Go 共享库。CDEF 由 `cffi_binding/build_binding.py` 从
`main.go` 的 cgo 前导块与 `//export` 指令推导，不存在手工维护的重复声明。
