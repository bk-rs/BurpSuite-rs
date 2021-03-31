# burpsuite-kit

* [Cargo package](https://crates.io/crates/burpsuite-kit)

## Dev

```
cargo clippy --all --all-features -- -D clippy::all
cargo +nightly clippy --all --all-features -- -D clippy::all

cargo fmt --all -- --check

cargo test --all --all-features -- --nocapture
```

```
RUST_LOG=debug cargo run -p burpsuite_kit_http_history
```

```
cargo build-all-features

cargo test-all-features -- --nocapture
```
