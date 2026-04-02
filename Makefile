.PHONY: build test lint clean release completions deny coverage doc check fmt

BINARY   := shadowforge
TARGET   := target/release/$(BINARY)
VERSION  := $(shell cat VERSION 2>/dev/null || echo "0.1.0")

# ─── Primary targets ──────────────────────────────────────────────────────────

build:
	cargo build --workspace --all-features

release:
	cargo build --release --all-features
	@echo "Binary: $(TARGET)"
	@ls -lh $(TARGET)

test:
	cargo test --workspace --all-features

lint:
	cargo clippy --workspace --all-features -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clean:
	cargo clean
	rm -rf coverage/ completions/

check: fmt-check lint test deny
	@echo "All checks passed."

# ─── Supply chain ─────────────────────────────────────────────────────────────

deny:
	cargo deny check

# ─── Coverage ─────────────────────────────────────────────────────────────────

coverage:
	cargo tarpaulin --workspace --all-features \
		--out Html --output-dir coverage/ \
		--exclude-files "src/interface/*" \
		--timeout 300
	@echo "Coverage report: coverage/tarpaulin-report.html"

# ─── Shell completions ────────────────────────────────────────────────────────

completions: build
	mkdir -p completions
	./$(TARGET) completions bash > completions/$(BINARY).bash
	./$(TARGET) completions zsh  > completions/_$(BINARY)
	./$(TARGET) completions fish > completions/$(BINARY).fish
	@echo "Completions written to completions/"

# ─── Documentation ────────────────────────────────────────────────────────────

doc:
	cargo doc --workspace --all-features --no-deps --open

# ─── Corpus (sample index build for testing) ──────────────────────────────────

corpus-build-sample: build
	@echo "Building sample corpus index from tests/corpus/..."
	./$(TARGET) corpus build --dir tests/corpus/

# ─── Install ──────────────────────────────────────────────────────────────────

install: release
	install -Dm755 $(TARGET) ~/.local/bin/$(BINARY)
	@echo "Installed to ~/.local/bin/$(BINARY)"

# ─── Version ──────────────────────────────────────────────────────────────────

version:
	@echo $(VERSION)
