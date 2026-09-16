# Jabuti 1.0.0

Jabuti é um núcleo reutilizável de **proteção criptográfica local** e
**crypto-shredding** para mensageiros e outros aplicativos que armazenam
conteúdo sensível.

```text
plaintext -> RAM -> AES-256-GCM -> ciphertext -> disco

DELETE:
  autenticar registro
  -> destruir chave individual
  -> confirmar ausência da chave
  -> apagar ciphertext lógico
  -> limpar cache/preview/índice
  -> propagar tombstone quando aplicável
```

## Componentes

- `jabuti-core`: formato, AEAD, AAD, limites, crypto-shredding e cofre em RAM para testes;
- `jabuti-cofre-sistema`: cofre persistente nativo do SO;
- `jabuti-cli`: diagnóstico e autotestes sem imprimir plaintext.

## Backends nativos

- Linux: Secret Service via zbus;
- Windows: Credential Manager;
- macOS: Keychain;
- iOS: Protected Data Keychain;
- Android: armazenamento cifrado com chave no Android Keystore.

O backend é classificado como `CofreDoSistema`. Isso **não significa** que toda
plataforma/dispositivo garanta chave hardware-backed.

No Android, o contexto NDK precisa estar inicializado antes da criação do cofre,
conforme exige o backend `android-native-keyring-store`.

## Requisitos

- Rust 1.88+;
- Linux desktop com implementação Secret Service disponível e desbloqueada;
- permissões/entitlements normais do Keychain/Keystore nas plataformas móveis.

## Testes obrigatórios

```bash
./scripts/testar-producao.sh
```

O script executa:

```text
cargo fmt --check
cargo test --workspace --all-targets
cargo clippy -D warnings
cargo doc -D warnings
jabuti autoteste
```

Para incluir o teste real do cofre do SO:

```bash
JABUTI_TESTAR_COFRE_SISTEMA=1 ./scripts/testar-producao.sh
```

No Manjaro/KDE ou GNOME, execute isso dentro da sessão gráfica normal, com o
Secret Service/KWallet/gnome-keyring desbloqueado.

## Uso em produção

```rust
use jabuti_cofre_sistema::CofreSistema;
use jabuti_core::{CategoriaRegistro, Jabuti};
use zeroize::Zeroizing;

let cofre = CofreSistema::novo(
    "br.mpma.nheenga.jabuti",
    "perfil-local-do-dispositivo",
)?;

let jabuti = Jabuti::novo(cofre);
let texto = Zeroizing::new(b"mensagem confidencial".to_vec());

let registro = jabuti.proteger(
    "msg-123",
    CategoriaRegistro::Mensagem,
    &texto,
    b"conversa:456",
)?;

// Persistir apenas `registro`.

let aberto = jabuti.abrir(&registro)?;

// Ao excluir:
let tombstone = jabuti.destruir(&registro)?;
// Só depois: apagar ciphertext lógico + caches + índices + previews.
```

### Regra importante

`contexto_extra` faz parte do AAD, porém é persistido em claro no
`RegistroCifrado`. Use apenas metadados não secretos. Nunca coloque o texto da
mensagem, chave ou conteúdo de anexo nesse campo.

## O que os testes cobrem

- round-trip AES-256-GCM;
- ausência de plaintext no JSON persistido;
- autenticação de AAD;
- detecção de adulteração de ciphertext;
- chave e nonce independentes por registro;
- anexo de 12 MiB;
- limites defensivos;
- serialização/desserialização;
- concorrência;
- rollback de chave quando a cifragem falha;
- exclusão idempotente;
- prevenção contra `id_chave` adulterado apagar a chave de outro registro;
- integração real com cofre nativo (teste opt-in).

## Produção e alegações de segurança

Esta versão é uma **base de produção**, mas software criptográfico não deve ser
tratado como “forense-impossível” apenas porque os testes passam. Antes de uma
alegação forte contra ferramentas forenses, execute a checklist de release em
cada plataforma, teste backups/snapshots e faça revisão criptográfica externa.

Leia `SECURITY.md` e `docs/MODELO_DE_AMEACAS.md`.

## Linux: backend criptográfico do Secret Service

O backend Linux usa `zbus-secret-service-keyring-store` com a feature `crypto-rust` habilitada explicitamente:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
zbus-secret-service-keyring-store = { version = "1.0.3", default-features = false, features = ["crypto-rust"] }
```

Isso é necessário nas versões atuais do `secret-service`, que exigem a seleção explícita de `crypto-rust` ou `crypto-openssl`. O Jabuti escolhe `crypto-rust` para evitar uma dependência adicional de OpenSSL.

