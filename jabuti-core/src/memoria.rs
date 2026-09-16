use std::{collections::HashMap, sync::RwLock};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CofreDeChaves, ErroJabuti, IdChave, NivelProtecao, PacoteCifrado, Resultado};

/// Cofre exclusivamente para testes e desenvolvimento.
///
/// As chaves vivem em RAM e desaparecem no encerramento do processo. Não use
/// este cofre para histórico persistente de produção.
#[derive(Default)]
pub struct CofreMemoria {
    chaves: RwLock<HashMap<IdChave, ChaveMemoria>>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ChaveMemoria([u8; 32]);

impl CofreMemoria {
    pub fn novo() -> Self {
        Self::default()
    }
}

impl CofreDeChaves for CofreMemoria {
    fn criar_chave(&self, id: &IdChave) -> Resultado<()> {
        let mut mapa = self.chaves.write().map_err(|_| ErroJabuti::Sincronizacao)?;

        if mapa.contains_key(id) {
            return Err(ErroJabuti::ChaveJaExiste(id.como_str().to_owned()));
        }

        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        mapa.insert(id.clone(), ChaveMemoria(bytes));
        Ok(())
    }

    fn cifrar(&self, id: &IdChave, plaintext: &[u8], aad: &[u8]) -> Resultado<PacoteCifrado> {
        let mapa = self.chaves.read().map_err(|_| ErroJabuti::Sincronizacao)?;
        let chave = mapa
            .get(id)
            .ok_or_else(|| ErroJabuti::ChaveNaoEncontrada(id.como_str().to_owned()))?;

        let cifra = Aes256Gcm::new_from_slice(&chave.0).map_err(|_| ErroJabuti::FalhaCifragem)?;
        let mut nonce_bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let conteudo_cifrado = cifra
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| ErroJabuti::FalhaCifragem)?;

        Ok(PacoteCifrado {
            nonce: nonce_bytes.to_vec(),
            conteudo_cifrado,
        })
    }

    fn decifrar(
        &self,
        id: &IdChave,
        pacote: &PacoteCifrado,
        aad: &[u8],
    ) -> Resultado<Zeroizing<Vec<u8>>> {
        if pacote.nonce.len() != 12 {
            return Err(ErroJabuti::RegistroInvalido(
                "nonce AES-GCM deve possuir 12 bytes".to_owned(),
            ));
        }

        let mapa = self.chaves.read().map_err(|_| ErroJabuti::Sincronizacao)?;
        let chave = mapa
            .get(id)
            .ok_or_else(|| ErroJabuti::ChaveNaoEncontrada(id.como_str().to_owned()))?;

        let cifra = Aes256Gcm::new_from_slice(&chave.0).map_err(|_| ErroJabuti::FalhaDecifragem)?;
        let nonce = Nonce::from_slice(&pacote.nonce);

        let plaintext = cifra
            .decrypt(
                nonce,
                Payload {
                    msg: &pacote.conteudo_cifrado,
                    aad,
                },
            )
            .map_err(|_| ErroJabuti::FalhaDecifragem)?;

        Ok(Zeroizing::new(plaintext))
    }

    fn destruir_chave(&self, id: &IdChave) -> Resultado<()> {
        let mut mapa = self.chaves.write().map_err(|_| ErroJabuti::Sincronizacao)?;
        if let Some(mut chave) = mapa.remove(id) {
            chave.zeroize();
        }
        Ok(())
    }

    fn existe_chave(&self, id: &IdChave) -> Resultado<bool> {
        let mapa = self.chaves.read().map_err(|_| ErroJabuti::Sincronizacao)?;
        Ok(mapa.contains_key(id))
    }

    fn nivel_protecao(&self) -> NivelProtecao {
        NivelProtecao::SoftwareTemporario
    }
}
