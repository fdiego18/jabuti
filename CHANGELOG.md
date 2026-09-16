# Changelog

## 1.0.3 — 2026-09-16

- Corrige `clippy::needless-borrows-for-generic-args` na codificação Base64 da chave.
- Usa `chave.as_slice()` em vez de `&chave`; isso satisfaz o Clippy sem mover/copiar o array secreto por valor.
- Mantém a zeroização explícita do buffer original da chave após persistência no cofre do sistema.

## 1.0.2 — 2026-09-16

- Corrige o armazenamento do backend nativo para preservar os auto-traits `Send + Sync`.
- Usa o alias oficial `keyring_core::api::CredentialStore`, que equivale a `dyn CredentialStoreApi + Send + Sync`.
- Mantém `CofreDeChaves: Send + Sync` sem enfraquecer a segurança de concorrência do núcleo.

## 1.0.1 - 2026-09-16

- Corrige o backend Linux Secret Service habilitando explicitamente `crypto-rust` no `zbus-secret-service-keyring-store`.
- Evita a falha de compilação do `secret-service 5.2.x`: `Please enable a cryptography feature`.
- Mantém o backend totalmente Rust, sem dependência de OpenSSL para a sessão Secret Service.

## 1.0.0 — 2026-09-16

- núcleo endurecido para produção;
- limites defensivos de tamanho;
- AAD com separação explícita de domínio;
- validação completa de registros persistidos;
- verificação de autenticidade AEAD em `verificar_integridade`;
- `destruir()` autentica o registro antes de remover uma chave existente;
- destruição idempotente com comprovante/tombstone;
- cofre nativo para Linux, Windows, macOS, iOS e Android;
- nomes de credenciais derivados por SHA-256 para reduzir vazamento de IDs;
- buffers de plaintext/chave protegidos por `Zeroizing` quando controlados pelo Jabuti;
- CLI de autoteste sem impressão de plaintext;
- testes de segurança, concorrência, rollback e anexo de 12 MiB;
- teste opt-in contra o cofre real da plataforma;
- CI multiplataforma com fmt, test, clippy, docs e cargo-audit;
- scripts de validação para Linux/macOS e Windows;
- documentação de arquitetura, ameaças e checklist de release.
