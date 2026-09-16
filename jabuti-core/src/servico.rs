use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    CategoriaRegistro, CofreDeChaves, ComprovanteDestruicao, ConfiguracaoJabuti, ErroJabuti,
    EstadoIntegridade, IdChave, PacoteCifrado, RegistroCifrado, Resultado,
};

const VERSAO_REGISTRO: u16 = 1;
const VERSAO_TOMBSTONE: u16 = 1;
const ALGORITMO: &str = "AES-256-GCM";
const TAG_GCM_BYTES: usize = 16;

pub struct Jabuti<C: CofreDeChaves> {
    cofre: Arc<C>,
    configuracao: ConfiguracaoJabuti,
}

#[derive(Serialize)]
struct ContextoAutenticado<'a> {
    dominio: &'static str,
    versao: u16,
    algoritmo: &'static str,
    id_registro: &'a str,
    id_chave: &'a str,
    categoria: &'a CategoriaRegistro,
    contexto_extra_base64: String,
}

impl<C: CofreDeChaves> Clone for Jabuti<C> {
    fn clone(&self) -> Self {
        Self {
            cofre: Arc::clone(&self.cofre),
            configuracao: self.configuracao.clone(),
        }
    }
}

impl<C: CofreDeChaves> Jabuti<C> {
    pub fn novo(cofre: C) -> Self {
        Self::com_configuracao(cofre, ConfiguracaoJabuti::default())
    }

    pub fn com_configuracao(cofre: C, configuracao: ConfiguracaoJabuti) -> Self {
        Self {
            cofre: Arc::new(cofre),
            configuracao,
        }
    }

    pub fn com_cofre_compartilhado(cofre: Arc<C>, configuracao: ConfiguracaoJabuti) -> Self {
        Self {
            cofre,
            configuracao,
        }
    }

    /// Cifra o conteúdo antes da persistência.
    ///
    /// O chamador deve manter `plaintext` somente em RAM e, quando possuir o
    /// buffer, usar `Zeroizing<Vec<u8>>` ou outra estratégia de zeroização.
    pub fn proteger(
        &self,
        id_registro: impl Into<String>,
        categoria: CategoriaRegistro,
        plaintext: &[u8],
        contexto_extra: &[u8],
    ) -> Resultado<RegistroCifrado> {
        let id_registro = id_registro.into();
        self.validar_entrada(&id_registro, plaintext, contexto_extra)?;

        let id_chave = IdChave::novo(format!(
            "jabuti:{}:{}:{}",
            categoria.rotulo_chave(),
            id_registro,
            Uuid::new_v4()
        ));

        let aad = montar_aad(
            VERSAO_REGISTRO,
            &id_registro,
            &id_chave,
            &categoria,
            contexto_extra,
        )?;

        self.cofre.criar_chave(&id_chave)?;

        let pacote = match self.cofre.cifrar(&id_chave, plaintext, &aad) {
            Ok(pacote) => pacote,
            Err(erro) => {
                let _ = self.cofre.destruir_chave(&id_chave);
                return Err(erro);
            }
        };

        if pacote.nonce.len() != 12 || pacote.conteudo_cifrado.len() < TAG_GCM_BYTES {
            let _ = self.cofre.destruir_chave(&id_chave);
            return Err(ErroJabuti::RegistroInvalido(
                "cofre retornou pacote AEAD inválido".to_owned(),
            ));
        }

        Ok(RegistroCifrado {
            versao: VERSAO_REGISTRO,
            id_registro,
            id_chave,
            categoria,
            algoritmo: ALGORITMO.to_owned(),
            nonce: pacote.nonce,
            sha256_cifrado: sha256_hex(&pacote.conteudo_cifrado),
            conteudo_cifrado: pacote.conteudo_cifrado,
            contexto_extra: contexto_extra.to_vec(),
            criado_em_utc: Utc::now(),
        })
    }

    /// Abre um registro autenticado e devolve o plaintext em um buffer que é
    /// zeroizado ao sair de escopo.
    pub fn abrir(&self, registro: &RegistroCifrado) -> Resultado<Zeroizing<Vec<u8>>> {
        self.validar_formato(registro)?;

        if sha256_hex(&registro.conteudo_cifrado) != registro.sha256_cifrado {
            return Err(ErroJabuti::IntegridadeInvalida);
        }

        if !self.cofre.existe_chave(&registro.id_chave)? {
            return Err(ErroJabuti::ChaveNaoEncontrada(
                registro.id_chave.como_str().to_owned(),
            ));
        }

        let aad = montar_aad(
            registro.versao,
            &registro.id_registro,
            &registro.id_chave,
            &registro.categoria,
            &registro.contexto_extra,
        )?;

        let pacote = PacoteCifrado {
            nonce: registro.nonce.clone(),
            conteudo_cifrado: registro.conteudo_cifrado.clone(),
        };

        self.cofre.decifrar(&registro.id_chave, &pacote, &aad)
    }

    /// Verifica formato, hash, existência da chave e autenticação AEAD/AAD.
    pub fn verificar_integridade(
        &self,
        registro: &RegistroCifrado,
    ) -> Resultado<EstadoIntegridade> {
        self.validar_formato(registro)?;

        if sha256_hex(&registro.conteudo_cifrado) != registro.sha256_cifrado {
            return Ok(EstadoIntegridade::HashDivergente);
        }

        if !self.cofre.existe_chave(&registro.id_chave)? {
            return Ok(EstadoIntegridade::ChaveAusente);
        }

        match self.abrir(registro) {
            Ok(plaintext) => {
                drop(plaintext);
                Ok(EstadoIntegridade::Integro)
            }
            Err(ErroJabuti::FalhaDecifragem) => Ok(EstadoIntegridade::AutenticacaoInvalida),
            Err(erro) => Err(erro),
        }
    }

    /// Destrói a chave do registro.
    ///
    /// Quando a chave ainda existe, o registro é autenticado antes da
    /// destruição. Isso impede que um registro adulterado aponte para a chave de
    /// outro registro e provoque a exclusão da chave errada.
    ///
    /// A operação é idempotente: se a chave já estiver ausente, retorna um novo
    /// comprovante com `chave_ja_ausente = true`.
    pub fn destruir(&self, registro: &RegistroCifrado) -> Resultado<ComprovanteDestruicao> {
        self.validar_formato(registro)?;

        let ja_ausente = !self.cofre.existe_chave(&registro.id_chave)?;

        if !ja_ausente {
            let plaintext = self.abrir(registro)?;
            drop(plaintext);
            self.cofre.destruir_chave(&registro.id_chave)?;

            if self.cofre.existe_chave(&registro.id_chave)? {
                return Err(ErroJabuti::CofreIndisponivel(
                    "o cofre informou sucesso, mas a chave ainda existe".to_owned(),
                ));
            }
        }

        Ok(ComprovanteDestruicao {
            versao: VERSAO_TOMBSTONE,
            id_registro: registro.id_registro.clone(),
            id_chave: registro.id_chave.clone(),
            sha256_cifrado: registro.sha256_cifrado.clone(),
            destruido_em_utc: Utc::now(),
            chave_ja_ausente: ja_ausente,
        })
    }

    pub fn cofre(&self) -> &C {
        self.cofre.as_ref()
    }

    pub fn configuracao(&self) -> &ConfiguracaoJabuti {
        &self.configuracao
    }

    fn validar_entrada(
        &self,
        id_registro: &str,
        plaintext: &[u8],
        contexto: &[u8],
    ) -> Resultado<()> {
        if id_registro.trim().is_empty() {
            return Err(ErroJabuti::RegistroInvalido(
                "id_registro não pode ser vazio".to_owned(),
            ));
        }
        if id_registro.len() > self.configuracao.tamanho_maximo_id {
            return Err(ErroJabuti::LimiteExcedido(format!(
                "id_registro excede {} bytes",
                self.configuracao.tamanho_maximo_id
            )));
        }
        if plaintext.len() > self.configuracao.tamanho_maximo_plaintext {
            return Err(ErroJabuti::LimiteExcedido(format!(
                "plaintext excede {} bytes",
                self.configuracao.tamanho_maximo_plaintext
            )));
        }
        if contexto.len() > self.configuracao.tamanho_maximo_contexto {
            return Err(ErroJabuti::LimiteExcedido(format!(
                "contexto_extra excede {} bytes",
                self.configuracao.tamanho_maximo_contexto
            )));
        }
        Ok(())
    }

    fn validar_formato(&self, registro: &RegistroCifrado) -> Resultado<()> {
        if registro.versao != VERSAO_REGISTRO {
            return Err(ErroJabuti::RegistroInvalido(format!(
                "versão {} não suportada",
                registro.versao
            )));
        }
        if registro.algoritmo != ALGORITMO {
            return Err(ErroJabuti::RegistroInvalido(format!(
                "algoritmo não suportado: {}",
                registro.algoritmo
            )));
        }
        if registro.id_registro.trim().is_empty() {
            return Err(ErroJabuti::RegistroInvalido("id_registro vazio".to_owned()));
        }
        if registro.id_registro.len() > self.configuracao.tamanho_maximo_id {
            return Err(ErroJabuti::LimiteExcedido(
                "id_registro persistido excede o limite".to_owned(),
            ));
        }
        if registro.id_chave.esta_vazio() {
            return Err(ErroJabuti::RegistroInvalido("id_chave vazio".to_owned()));
        }
        if registro.nonce.len() != 12 {
            return Err(ErroJabuti::RegistroInvalido(
                "nonce AES-GCM deve possuir 12 bytes".to_owned(),
            ));
        }
        if registro.conteudo_cifrado.len() < TAG_GCM_BYTES {
            return Err(ErroJabuti::RegistroInvalido(
                "ciphertext menor que a tag GCM".to_owned(),
            ));
        }
        if registro.conteudo_cifrado.len()
            > self
                .configuracao
                .tamanho_maximo_plaintext
                .saturating_add(TAG_GCM_BYTES)
        {
            return Err(ErroJabuti::LimiteExcedido(
                "ciphertext persistido excede o limite".to_owned(),
            ));
        }
        if registro.contexto_extra.len() > self.configuracao.tamanho_maximo_contexto {
            return Err(ErroJabuti::LimiteExcedido(
                "contexto_extra persistido excede o limite".to_owned(),
            ));
        }
        if registro.sha256_cifrado.len() != 64
            || !registro
                .sha256_cifrado
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(ErroJabuti::RegistroInvalido(
                "sha256_cifrado deve ser hexadecimal SHA-256".to_owned(),
            ));
        }
        Ok(())
    }
}

fn montar_aad(
    versao: u16,
    id_registro: &str,
    id_chave: &IdChave,
    categoria: &CategoriaRegistro,
    contexto_extra: &[u8],
) -> Resultado<Vec<u8>> {
    serde_json::to_vec(&ContextoAutenticado {
        dominio: "JABUTI-REGISTRO-AEAD-V1",
        versao,
        algoritmo: ALGORITMO,
        id_registro,
        id_chave: id_chave.como_str(),
        categoria,
        contexto_extra_base64: BASE64.encode(contexto_extra),
    })
    .map_err(|erro| ErroJabuti::FalhaSerializacao(erro.to_string()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}
