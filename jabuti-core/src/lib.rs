//! Jabuti: proteção criptográfica local e crypto-shredding reutilizável.
//!
//! Regra central:
//!
//! ```text
//! plaintext -> RAM -> AEAD -> ciphertext -> persistência
//!
//! DELETE:
//!   autenticar registro -> destruir chave -> apagar ciphertext lógico
//!   -> limpar caches/índices/previews -> propagar tombstone
//! ```
//!
//! O núcleo não conhece rede, banco, UI ou mensageiro. A guarda das chaves é
//! delegada a [`CofreDeChaves`].

#![forbid(unsafe_code)]

mod cofre;
mod configuracao;
mod erro;
mod memoria;
mod servico;
mod tipos;

pub use cofre::CofreDeChaves;
pub use configuracao::ConfiguracaoJabuti;
pub use erro::{ErroJabuti, Resultado};
pub use memoria::CofreMemoria;
pub use servico::Jabuti;
pub use tipos::{
    CategoriaRegistro, ComprovanteDestruicao, EstadoIntegridade, IdChave, NivelProtecao,
    PacoteCifrado, RegistroCifrado,
};
