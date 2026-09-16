use zeroize::Zeroizing;

use crate::{IdChave, NivelProtecao, PacoteCifrado, Resultado};

/// Contrato para um cofre de chaves.
///
/// A API deliberadamente não possui `obter_chave()`: aplicações usam o cofre
/// para executar cifragem/decifragem e destruição sem receber a chave pela API
/// pública do Jabuti. Implementações podem internamente usar uma chave
/// exportável (por exemplo, um Keychain/Secret Service) ou uma chave não
/// exportável/hardware-backed.
pub trait CofreDeChaves: Send + Sync {
    fn criar_chave(&self, id: &IdChave) -> Resultado<()>;

    fn cifrar(&self, id: &IdChave, plaintext: &[u8], aad: &[u8]) -> Resultado<PacoteCifrado>;

    fn decifrar(
        &self,
        id: &IdChave,
        pacote: &PacoteCifrado,
        aad: &[u8],
    ) -> Resultado<Zeroizing<Vec<u8>>>;

    /// Deve ser idempotente: destruir uma chave já ausente não é erro.
    fn destruir_chave(&self, id: &IdChave) -> Resultado<()>;

    fn existe_chave(&self, id: &IdChave) -> Resultado<bool>;

    fn nivel_protecao(&self) -> NivelProtecao;
}
