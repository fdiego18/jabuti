use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdChave(String);

impl IdChave {
    pub fn novo(valor: impl Into<String>) -> Self {
        Self(valor.into())
    }

    pub fn como_str(&self) -> &str {
        &self.0
    }

    pub fn esta_vazio(&self) -> bool {
        self.0.trim().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "tipo", content = "valor")]
pub enum CategoriaRegistro {
    Mensagem,
    Anexo,
    Cache,
    Outro(String),
}

impl CategoriaRegistro {
    pub fn rotulo_chave(&self) -> String {
        match self {
            Self::Mensagem => "mensagem".to_owned(),
            Self::Anexo => "anexo".to_owned(),
            Self::Cache => "cache".to_owned(),
            Self::Outro(valor) => {
                let limpo: String = valor
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                    .take(64)
                    .collect();
                if limpo.is_empty() {
                    "outro".to_owned()
                } else {
                    format!("outro-{limpo}")
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NivelProtecao {
    /// Chave não exportável ou diretamente protegida por hardware seguro.
    Hardware,
    /// Chave guardada pelo mecanismo seguro nativo do sistema operacional.
    CofreDoSistema,
    /// Somente RAM. Adequado para testes, não para persistência de produção.
    SoftwareTemporario,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacoteCifrado {
    pub nonce: Vec<u8>,
    pub conteudo_cifrado: Vec<u8>,
}

impl std::fmt::Debug for PacoteCifrado {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacoteCifrado")
            .field("nonce_len", &self.nonce.len())
            .field("conteudo_cifrado_len", &self.conteudo_cifrado.len())
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegistroCifrado {
    pub versao: u16,
    pub id_registro: String,
    pub id_chave: IdChave,
    pub categoria: CategoriaRegistro,
    pub algoritmo: String,
    pub nonce: Vec<u8>,
    pub conteudo_cifrado: Vec<u8>,
    pub sha256_cifrado: String,
    /// Metadado autenticado e persistido em claro. Não coloque segredos aqui.
    pub contexto_extra: Vec<u8>,
    pub criado_em_utc: DateTime<Utc>,
}

impl std::fmt::Debug for RegistroCifrado {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistroCifrado")
            .field("versao", &self.versao)
            .field("id_registro", &self.id_registro)
            .field("id_chave", &self.id_chave)
            .field("categoria", &self.categoria)
            .field("algoritmo", &self.algoritmo)
            .field("nonce_len", &self.nonce.len())
            .field("conteudo_cifrado_len", &self.conteudo_cifrado.len())
            .field("sha256_cifrado", &self.sha256_cifrado)
            .field("contexto_extra_len", &self.contexto_extra.len())
            .field("criado_em_utc", &self.criado_em_utc)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EstadoIntegridade {
    Integro,
    ChaveAusente,
    HashDivergente,
    AutenticacaoInvalida,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprovanteDestruicao {
    pub versao: u16,
    pub id_registro: String,
    pub id_chave: IdChave,
    pub sha256_cifrado: String,
    pub destruido_em_utc: DateTime<Utc>,
    /// `true` quando a chamada foi repetida e a chave já não existia.
    pub chave_ja_ausente: bool,
}
