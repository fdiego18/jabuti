#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[1/5] cargo fmt"
cargo fmt --all -- --check

echo "[2/5] cargo test"
cargo test --workspace --all-targets

echo "[3/5] cargo clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "[4/5] cargo doc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

echo "[5/5] autoteste CLI"
cargo run -p jabuti-cli -- autoteste

if [[ "${JABUTI_TESTAR_COFRE_SISTEMA:-0}" == "1" ]]; then
  echo "[extra] cofre real do sistema"
  cargo test -p jabuti-cofre-sistema --test cofre_real -- --ignored --nocapture
  cargo run -p jabuti-cli -- autoteste-sistema
else
  echo "[extra] cofre real não executado (defina JABUTI_TESTAR_COFRE_SISTEMA=1)"
fi

echo "Todos os testes obrigatórios concluídos."
