//! Cofre persistente do Jabuti baseado no armazenamento seguro nativo do SO.
//!
//! Backends:
//! - Linux: Secret Service via zbus;
//! - Windows: Credential Manager;
//! - macOS: Keychain;
//! - iOS: Protected Data Keychain;
//! - Android: SharedPreferences cifrado por chave do Android Keystore.
//!
//! O nível reportado é `CofreDoSistema`. Isso não implica que a chave seja
//! hardware-backed em todo dispositivo.

#![forbid(unsafe_code)]

use std::sync::Arc;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use jabuti_core::{CofreDeChaves, ErroJabuti, IdChave, NivelProtecao, PacoteCifrado, Resultado};
use keyring_core::{Entry, Error as ErroKeyring, api::CredentialStore};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const TAMANHO_CHAVE: usize = 32;

pub struct CofreSistema {
    store: Arc<CredentialStore>,
    servico: String,
    namespace: String,
}

impl CofreSistema {
    pub fn novo(servico: impl Into<String>, namespace: impl Into<String>) -> Resultado<Self> {
        let servico = servico.into();
        let namespace = namespace.into();

        validar_nome("servico", &servico)?;
        validar_nome("namespace", &namespace)?;

        Ok(Self {
            store: criar_store_nativo()?,
            servico,
            namespace,
        })
    }

    /// Faz uma operação não destrutiva para confirmar que o backend nativo
    /// pode construir uma entrada. Não cria uma credencial.
    pub fn diagnosticar(&self) -> Resultado<()> {
        self.entrada_por_usuario("jabuti-diagnostico")?;
        Ok(())
    }

    pub fn nome_backend(&self) -> &'static str {
        #[cfg(target_os = "linux")]
        {
            return "Secret Service (zbus)";
        }
        #[cfg(target_os = "windows")]
        {
            return "Windows Credential Manager";
        }
        #[cfg(target_os = "macos")]
        {
            return "macOS Keychain";
        }
        #[cfg(target_os = "ios")]
        {
            return "iOS Protected Data Keychain";
        }
        #[cfg(target_os = "android")]
        {
            return "Android Keystore + SharedPreferences";
        }
        #[allow(unreachable_code)]
        "não suportado"
    }

    fn entrada(&self, id: &IdChave) -> Resultado<Entry> {
        let usuario = nome_entrada(&self.namespace, id);
        self.entrada_por_usuario(&usuario)
    }

    fn entrada_por_usuario(&self, usuario: &str) -> Resultado<Entry> {
        self.store
            .build(&self.servico, usuario, None)
            .map_err(mapear_erro_keyring)
    }

    fn carregar_chave(&self, id: &IdChave) -> Resultado<Zeroizing<Vec<u8>>> {
        let entrada = self.entrada(id)?;
        let codificada = Zeroizing::new(
            entrada
                .get_password()
                .map_err(|e| mapear_erro_keyring_com_id(e, id))?,
        );
        let bytes = Zeroizing::new(
            BASE64
                .decode(codificada.as_bytes())
                .map_err(|_| ErroJabuti::ChaveCorrompida)?,
        );
        if bytes.len() != TAMANHO_CHAVE {
            return Err(ErroJabuti::ChaveCorrompida);
        }
        Ok(bytes)
    }
}

impl CofreDeChaves for CofreSistema {
    fn criar_chave(&self, id: &IdChave) -> Resultado<()> {
        let entrada = self.entrada(id)?;

        match entrada.get_password() {
            Ok(_) => return Err(ErroJabuti::ChaveJaExiste(id.como_str().to_owned())),
            Err(ErroKeyring::NoEntry) => {}
            Err(erro) => return Err(mapear_erro_keyring_com_id(erro, id)),
        }

        let mut chave = [0_u8; TAMANHO_CHAVE];
        OsRng.fill_bytes(&mut chave);
        let codificada = Zeroizing::new(BASE64.encode(chave));

        let resultado = entrada
            .set_password(&codificada)
            .map_err(mapear_erro_keyring);
        chave.zeroize();
        resultado
    }

    fn cifrar(&self, id: &IdChave, plaintext: &[u8], aad: &[u8]) -> Resultado<PacoteCifrado> {
        let chave = self.carregar_chave(id)?;
        let cifra = Aes256Gcm::new_from_slice(&chave).map_err(|_| ErroJabuti::ChaveCorrompida)?;

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

        let chave = self.carregar_chave(id)?;
        let cifra = Aes256Gcm::new_from_slice(&chave).map_err(|_| ErroJabuti::ChaveCorrompida)?;
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
        let entrada = self.entrada(id)?;
        match entrada.delete_credential() {
            Ok(()) | Err(ErroKeyring::NoEntry) => Ok(()),
            Err(erro) => Err(mapear_erro_keyring_com_id(erro, id)),
        }
    }

    fn existe_chave(&self, id: &IdChave) -> Resultado<bool> {
        let entrada = self.entrada(id)?;
        match entrada.get_password() {
            Ok(valor) => {
                let valor = Zeroizing::new(valor);
                let bytes = Zeroizing::new(
                    BASE64
                        .decode(valor.as_bytes())
                        .map_err(|_| ErroJabuti::ChaveCorrompida)?,
                );
                if bytes.len() != TAMANHO_CHAVE {
                    return Err(ErroJabuti::ChaveCorrompida);
                }
                Ok(true)
            }
            Err(ErroKeyring::NoEntry) => Ok(false),
            Err(erro) => Err(mapear_erro_keyring_com_id(erro, id)),
        }
    }

    fn nivel_protecao(&self) -> NivelProtecao {
        NivelProtecao::CofreDoSistema
    }
}

fn validar_nome(campo: &str, valor: &str) -> Resultado<()> {
    if valor.trim().is_empty() {
        return Err(ErroJabuti::CofreIndisponivel(format!(
            "{campo} não pode ser vazio"
        )));
    }
    if valor.len() > 200 {
        return Err(ErroJabuti::CofreIndisponivel(format!(
            "{campo} excede 200 bytes"
        )));
    }
    Ok(())
}

fn nome_entrada(namespace: &str, id: &IdChave) -> String {
    let mut hash = Sha256::new();
    hash.update(b"JABUTI-KEY-ID-V1\0");
    hash.update(namespace.as_bytes());
    hash.update(b"\0");
    hash.update(id.como_str().as_bytes());
    let digest = hash.finalize();
    format!("v1-{digest:x}")
}

fn mapear_erro_keyring(erro: ErroKeyring) -> ErroJabuti {
    match erro {
        ErroKeyring::NoEntry => ErroJabuti::ChaveNaoEncontrada("entrada nativa".to_owned()),
        outro => ErroJabuti::CofreIndisponivel(outro.to_string()),
    }
}

fn mapear_erro_keyring_com_id(erro: ErroKeyring, id: &IdChave) -> ErroJabuti {
    match erro {
        ErroKeyring::NoEntry => ErroJabuti::ChaveNaoEncontrada(id.como_str().to_owned()),
        outro => ErroJabuti::CofreIndisponivel(outro.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn criar_store_nativo() -> Resultado<Arc<CredentialStore>> {
    let store = zbus_secret_service_keyring_store::Store::new().map_err(mapear_erro_keyring)?;
    let store: Arc<CredentialStore> = store;
    Ok(store)
}

#[cfg(target_os = "windows")]
fn criar_store_nativo() -> Resultado<Arc<CredentialStore>> {
    let store = windows_native_keyring_store::Store::new().map_err(mapear_erro_keyring)?;
    let store: Arc<CredentialStore> = store;
    Ok(store)
}

#[cfg(target_os = "macos")]
fn criar_store_nativo() -> Resultado<Arc<CredentialStore>> {
    let store = apple_native_keyring_store::keychain::Store::new().map_err(mapear_erro_keyring)?;
    let store: Arc<CredentialStore> = store;
    Ok(store)
}

#[cfg(target_os = "ios")]
fn criar_store_nativo() -> Resultado<Arc<CredentialStore>> {
    let store = apple_native_keyring_store::protected::Store::new().map_err(mapear_erro_keyring)?;
    let store: Arc<CredentialStore> = store;
    Ok(store)
}

#[cfg(target_os = "android")]
fn criar_store_nativo() -> Resultado<Arc<CredentialStore>> {
    let store = android_native_keyring_store::Store::new().map_err(mapear_erro_keyring)?;
    let store: Arc<CredentialStore> = store;
    Ok(store)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios",
    target_os = "android"
)))]
fn criar_store_nativo() -> Resultado<Arc<CredentialStore>> {
    Err(ErroJabuti::CofreIndisponivel(
        "plataforma sem backend Jabuti nativo".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nome_da_entrada_nao_expoe_id_original() {
        let id = IdChave::novo("jabuti:mensagem:segredo-interno:123");
        let nome = nome_entrada("perfil-A", &id);
        assert!(nome.starts_with("v1-"));
        assert_eq!(nome.len(), 67);
        assert!(!nome.contains("segredo-interno"));
    }

    #[test]
    fn namespaces_geram_entradas_distintas() {
        let id = IdChave::novo("mesma-chave");
        assert_ne!(nome_entrada("perfil-A", &id), nome_entrada("perfil-B", &id));
    }
}
