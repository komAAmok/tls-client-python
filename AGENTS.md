# Repository ownership rules

## Upstream-owned code (read-only by default)

The Go engine and its tests/examples are synchronized from
`https://github.com/bogdanfinn/tls-client.git` (`upstream`). Do not edit these
areas during ordinary project work. Update them only through an explicit
upstream-sync task:

- root Go files, except `tcp_fingerprint.go`, `tcp_socket_unix.go`, and
  `tcp_socket_windows.go`, and `tcp_socket_darwin_test.go`
- `bandwidth/`, `profiles/`, `cffi_src/`, `cffi_dist/`, `example/`, and `tests/`

When a local feature must touch an upstream-owned file, keep the change
minimal and record it in `UPSTREAM_SYNC.md` under **Local overlay points**.

## Local-owned code

Normal project changes should be limited to these areas unless the user
explicitly asks otherwise:

- `tls_client/`
- `cffi_binding/`
- `benchmarks/`
- `python_tests/`
- Python packaging files and `Readme.md`
- the four `tcp_*` local extension files listed above
- `.github/workflows/build_workflow.yml`

## Upstream sync procedure

1. Require a clean worktree and create `backup/pre-upstream-YYYYMMDD`.
2. Run `git fetch upstream --prune`, then
   `git merge --no-ff upstream/master` (never squash or rebase upstream).
3. Preserve local-owned files and reconcile only the documented overlay
   points; do not hand-rewrite conflict-free upstream files.
4. Run the checks documented in `UPSTREAM_SYNC.md`.
5. Update only the sync commit/date and overlay list in `UPSTREAM_SYNC.md`.
