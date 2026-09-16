use thiserror::Error;

pub type Resultado<T> = std::result::Result<T, ErroJabuti>;

#[derive(Debug, Error)]
pub enum ErroJabuti {
    #[error("chave já existe: {0}")]
    ChaveJaExiste(String),

    #[error("chave não encontrada: {0}")]
    ChaveNaoEncontrada(String),

    #[error("material de chave inválido ou corrompido")]
    ChaveCorrompida,

    #[error("registro inválido: {0}")]
    RegistroInvalido(String),

    #[error("limite excedido: {0}")]
    LimiteExcedido(String),

    #[error("falha de integridade do ciphertext")]
    IntegridadeInvalida,

    #[error("falha ao cifrar conteúdo")]
    FalhaCifragem,

    #[error("falha ao decifrar conteúdo ou autenticar AAD")]
    FalhaDecifragem,

    #[error("falha ao serializar contexto autenticado: {0}")]
    FalhaSerializacao(String),

    #[error("cofre de chaves indisponível: {0}")]
    CofreIndisponivel(String),

    #[error("erro interno de sincronização")]
    Sincronizacao,
}
