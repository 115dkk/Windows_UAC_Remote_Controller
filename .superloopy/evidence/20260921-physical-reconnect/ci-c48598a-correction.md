# c48598a CI correction

ROOT observed Android Rust Clippy job106359637661 in Quality35607963597 fail
clippy::manual_async_fn at connectivity.rs282. The preceding patch's explicit
impl Future + Send wrapper is lint-equivalent to async fn under this toolchain.

ROOT applied the suggested async fn form and formatted the source. Rendezvous
still uses owned network cancellation; synchronous attachment still checks the
exact cancellation token after native owner admission. The production
JoinSet::spawn retains the compiler-enforced Send requirement. No diagnostic
filter, allow attribute or gate change was made. Exact new-SHA CI is required.

The separately running restricted same-signer measurement APK35607953359 builds
c48598a637eb7352687550c0de3a450ce57e0096. If used for a physical trial, that
artifact's source/signer/hash must be recorded explicitly. It is an internal
measurement candidate, not evidence that the new source or release gates passed.
