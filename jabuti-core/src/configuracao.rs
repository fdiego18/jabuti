/// Limites defensivos do núcleo Jabuti.
///
/// O padrão aceita com folga anexos de 12 MiB sem permitir alocações sem limite
/// quando registros são recebidos de armazenamento não confiável.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguracaoJabuti {
    pub tamanho_maximo_plaintext: usize,
    pub tamanho_maximo_contexto: usize,
    pub tamanho_maximo_id: usize,
}

impl Default for ConfiguracaoJabuti {
    fn default() -> Self {
        Self {
            tamanho_maximo_plaintext: 32 * 1024 * 1024,
            tamanho_maximo_contexto: 16 * 1024,
            tamanho_maximo_id: 512,
        }
    }
}
