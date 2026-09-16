$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "[1/5] cargo fmt"
cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[2/5] cargo test"
cargo test --workspace --all-targets
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[3/5] cargo clippy"
cargo clippy --workspace --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[4/5] cargo doc"
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --workspace --no-deps
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Remove-Item Env:RUSTDOCFLAGS

Write-Host "[5/5] autoteste CLI"
cargo run -p jabuti-cli -- autoteste
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($env:JABUTI_TESTAR_COFRE_SISTEMA -eq "1") {
    Write-Host "[extra] cofre real do sistema"
    cargo test -p jabuti-cofre-sistema --test cofre_real -- --ignored --nocapture
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    cargo run -p jabuti-cli -- autoteste-sistema
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "Todos os testes obrigatórios concluídos."
