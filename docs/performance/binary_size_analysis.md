# 二进制体积分析 · Binary Size Analysis

## 1. 实测数据

环境：linux/amd64，Go 1.27.4，`tls_client/bin/tls-client-linux-amd64.so`
（CI 重建产物，14,102,944 字节，ABI 4；md5 随每次 CI 重建变化）。

审计当日的本地构建产物为 14,095,240 字节（md5 `5575630d…`），两者相差约 7.7 KB，
ABI 均为 4、导出符号集一致（§4 有校验）。段构成以本地构建为准（同一源码、同参数）：

```
14,095,240  本地按 build_binding.py 参数构建
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
tls-client-linux-amd64.so          14,102,944
tls-client-linux-amd64-musl.so     14,086,176
tls-client-linux-arm64.so          13,152,928
tls-client-linux-arm64-musl.so     13,086,928
tls-client-linux-arm.so            13,285,204
tls-client-linux-arm-musl.so       13,223,496
tls-client-linux-386.so            13,180,808
tls-client-darwin-amd64.dylib      12,805,536
tls-client-darwin-arm64.dylib      11,901,440
tls-client-windows-amd64.dll       13,069,312
tls-client-windows-arm64.dll       11,944,960
tls-client-windows-386.dll         12,626,944
合计                              156,466,676
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
  该记录的基线（13,984,760）与当前产物的差异来自后续 upstream 同步，不是回退。
* `profile` build tag：`runtime/pprof` + `runtime/debug`（约 230 KB）默认不编入。

## 4. 可复现性与 CI 产物校验

### 4.1 本地构建可复现

用 `cffi_binding/build_binding.py` 的参数（`-s -w -buildid= -trimpath -buildvcs=false
-tags=netgo,osusergo -buildmode=c-shared`）在审计日重建，产物与仓库内当时的库
**逐字节相同**：

```
5575630d95c865f91e70259165974601  /tmp/build/verify.so
5575630d95c865f91e70259165974601  tls_client/bin/tls-client-linux-amd64.so   （审计当日）
```

### 4.2 CI 产物不是本地可逐字节复现的

CI 重建后产物变为 14,102,944 字节。照抄 CI 的完整参数（含
`-gcflags/-asmflags=-trimpath`、`CGO_LDFLAGS` 与 `strip -R .comment -R .note.GNU-stack --strip-unneeded`）
在本机重建得到 14,127,600 字节，**仍不相同**。

已定位到的差异来源：内嵌 `.go.buildinfo` 会记录 `-trimpath` 与 `-gcflags` 的**字面路径**——
CI 是 `/home/runner/work/tls-client-python/tls-client-python`，本机是工作目录。
把 trimpath 改成 CI 的字面值后差异从 ~31 KB 降到 ~24 KB，但没有归零，
剩余部分未定位（推测为 `ubuntu-latest` 的 binutils / gcc 版本差异影响 `strip` 结果）。

**因此不宣称"CI 产物可由源码逐字节复现"。** 能确认的是：

* 两者内嵌 buildinfo 的 `go1.27.4` 与**全部依赖版本表逐条相同**；
* `GetAbiVersion()` 均为 4；
* 完整导出符号集一致（见 §4.3）。

```
$ go version -m tls_client/bin/tls-client-linux-amd64.so | head -2
tls-client-linux-amd64.so: go1.27.4
    path  github.com/bogdanfinn/tls-client/cffi_binding
```

### 4.3 12 个平台的产物逐个校验（静态）

没有 11 个平台的可运行环境，只能做静态校验。三者都用**真正的导出表解析**，
不用 `strings` 猜：ELF 用 `nm -D`，Mach-O 用自写的 `LC_SYMTAB` 解析，
PE 用自写的导出目录解析（`nm -D` 读不了 Mach-O/PE，第一次用错工具得出了
"全部缺失"的错误结论，已纠正）。

| 校验项 | 结果 |
| --- | --- |
| 文件类型/架构与文件名一致 | 12/12 通过 |
| 15 个 ABI 导出齐全 | 12/12 通过（ELF 90–95 个导出符号，dylib 59 个外部符号，dll 24 个导出） |
| linux/amd64 可加载 + 274 项测试 | 通过 |

## 5. 本次结论：没有体积产出

在"不删功能"的前提下，本机没有找到可以安全再削的部分：

| 候选 | 可省 | 为什么不做 |
| --- | --- | --- |
| `-ldflags "-s -w"` | 已在用 | — |
| 删除 `.gopclntab` | 约 3.99 MB | panic 栈会失去函数名、反射失效。属于功能退化，拒绝。 |
| `profile` tag 关闭 | 已在默认关闭 | — |
| UPX 等可执行压缩 | 视比例 | 会改变加载方式、影响启动与安全软件兼容；未做任何实测，因此**不建议、不采用**。 |
| 精简构建档位 | — | 需求明确禁止用"精简档"冒充完整档，且会引入能力差异；本次不引入。 |

因此：**完整功能构建没有可安全再削的部分，本次未产出任何体积优化。**
仓库内 linux/amd64 产物的体积变化（14,095,240 → 14,102,944）来自 CI 重建，与本次改动无关。
不满足"体积下降"的验收项，如实记录为未达成，而不是用别的口径凑数。

## 6. CFFI 扩展

本项目是 **CFFI ABI mode**（`ffi.dlopen` + 运行期 `ffi.cdef`），
不生成编译型 C 扩展模块，所以 wheel 里没有额外的 `.so`/`.pyd` 扩展产物，
只有上表列出的 Go 共享库。CDEF 由 `cffi_binding/build_binding.py` 从
`main.go` 的 cgo 前导块与 `//export` 指令推导，不存在手工维护的重复声明。
