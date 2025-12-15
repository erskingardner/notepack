## notepack `just` tasks
##
## Install `just`: https://github.com/casey/just

# Show available recipes by default
default:
	@just --list

help:
	@just --list

# ---------- Rust basics ----------

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

check:
	cargo check --all-targets

test:
	cargo test

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

doc:
	cargo doc --no-deps

clean:
	cargo clean

# Run the stuff you'd typically want before pushing / opening a PR.
precommit: fmt-check clippy test

ci: precommit

# ---------- Benchmarks ----------

# Run all benches (Criterion). Pass-through args are supported, e.g.:
#   just bench -- --nocapture
#   just bench -- --help
bench *ARGS:
	cargo bench {{ARGS}}

bench-codec *ARGS:
	cargo bench --bench codec {{ARGS}}

bench-by-kind *ARGS:
	cargo bench --bench by_kind {{ARGS}}

# ---------- Fuzzing (cargo-fuzz) ----------

# List available fuzz targets.
fuzz-list:
	cd fuzz && cargo +nightly fuzz list

# Run a fuzz target. Example:
#   just fuzz-run notepack_parser
#   just fuzz-run notepack_decode_string -runs=0 crashes/id:000000,...
fuzz-run TARGET *ARGS:
	cd fuzz && cargo +nightly fuzz run {{TARGET}} {{ARGS}}

fuzz-run-parser *ARGS:
	just fuzz-run notepack_parser {{ARGS}}

fuzz-run-decode-string *ARGS:
	just fuzz-run notepack_decode_string {{ARGS}}

fuzz-run-encoder *ARGS:
	just fuzz-run notepack_encoder {{ARGS}}

# Clean fuzz artifacts for a target (or all targets if omitted).
fuzz-clean TARGET="":
	cd fuzz && cargo +nightly fuzz clean {{TARGET}}

# Convenience: show the README's fuzz tooling install snippet.
fuzz-install-help:
	@echo 'Install tooling:'
	@echo '  cargo install cargo-fuzz'
	@echo '  rustup toolchain install nightly'
	@echo '  rustup component add llvm-tools-preview --toolchain nightly'

