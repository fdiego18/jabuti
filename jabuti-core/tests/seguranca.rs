use std::sync::{Arc, Mutex};
use std::thread;

use jabuti_core::{
    CategoriaRegistro, CofreDeChaves, CofreMemoria, ConfiguracaoJabuti, ErroJabuti,
    EstadoIntegridade, IdChave, Jabuti, NivelProtecao, PacoteCifrado, Resultado,
};
use zeroize::Zeroizing;

#[test]
fn cifra_decifra_e_nao_serializa_plaintext() {
    let jabuti = Jabuti::novo(CofreMemoria::novo());
    let segredo = Zeroizing::new(b"JABUTI_SEGREDO_UNICO_7f6f3c".to_vec());

    let registro = jabuti
        .proteger(
            "msg-1",
            CategoriaRegistro::Mensagem,
            &segredo,
            b"conversa:42",
        )
        .expect("proteger");

    assert_ne!(registro.conteudo_cifrado.as_slice(), segredo.as_slice());
    let json = serde_json::to_string(&registro).expect("serializar");
    assert!(!json.contains("JABUTI_SEGREDO_UNICO_7f6f3c"));

    let aberto = jabuti.abrir(&registro).expect("abrir");
    assert_eq!(&*aberto, &*segredo);
}

#[test]
fn destruir_e_idempotente() {
    let jabuti = Jabuti::novo(CofreMemoria::novo());
    let registro = jabuti
        .proteger("msg-2", CategoriaRegistro::Mensagem, b"secreto", b"")
        .expect("proteger");

    let primeiro = jabuti.destruir(&registro).expect("destruir");
    assert!(!primeiro.chave_ja_ausente);
    assert_eq!(
        jabuti.verificar_integridade(&registro).expect("estado"),
        EstadoIntegridade::ChaveAusente
    );

    let segundo = jabuti.destruir(&registro).expect("destruir de novo");
    assert!(segundo.chave_ja_ausente);
    assert!(matches!(
        jabuti.abrir(&registro),
        Err(ErroJabuti::ChaveNaoEncontrada(_))
    ));
}

#[test]
fn adulterar_ciphertext_e_detectado() {
    let jabuti = Jabuti::novo(CofreMemoria::novo());
    let mut registro = jabuti
        .proteger("msg-3", CategoriaRegistro::Mensagem, b"conteudo", b"")
        .expect("proteger");

    registro.conteudo_cifrado[0] ^= 0x01;

    assert_eq!(
        jabuti.verificar_integridade(&registro).expect("estado"),
        EstadoIntegridade::HashDivergente
    );
    assert!(matches!(
        jabuti.abrir(&registro),
        Err(ErroJabuti::IntegridadeInvalida)
    ));
}

#[test]
fn adulterar_aad_e_detectado() {
    let jabuti = Jabuti::novo(CofreMemoria::novo());
    let mut registro = jabuti
        .proteger(
            "msg-4",
            CategoriaRegistro::Mensagem,
            b"conteudo",
            b"usuario:A",
        )
        .expect("proteger");

    registro.contexto_extra = b"usuario:B".to_vec();

    assert_eq!(
        jabuti.verificar_integridade(&registro).expect("estado"),
        EstadoIntegridade::AutenticacaoInvalida
    );
}

#[test]
fn registro_adulterado_nao_pode_apagar_chave_de_outro_registro() {
    let jabuti = Jabuti::novo(CofreMemoria::novo());
    let a = jabuti
        .proteger("A", CategoriaRegistro::Mensagem, b"alpha", b"")
        .expect("A");
    let b = jabuti
        .proteger("B", CategoriaRegistro::Mensagem, b"beta", b"")
        .expect("B");

    let mut falso = a.clone();
    falso.id_chave = b.id_chave.clone();

    assert!(matches!(
        jabuti.destruir(&falso),
        Err(ErroJabuti::FalhaDecifragem)
    ));

    let aberto_b = jabuti.abrir(&b).expect("B continua acessível");
    assert_eq!(&*aberto_b, b"beta");
}

#[test]
fn cada_registro_tem_chave_e_nonce_independentes() {
    let jabuti = Jabuti::novo(CofreMemoria::novo());
    let a = jabuti
        .proteger("mesmo", CategoriaRegistro::Mensagem, b"x", b"")
        .expect("A");
    let b = jabuti
        .proteger("mesmo", CategoriaRegistro::Mensagem, b"x", b"")
        .expect("B");

    assert_ne!(a.id_chave, b.id_chave);
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.conteudo_cifrado, b.conteudo_cifrado);
}

#[test]
fn suporta_anexo_de_12_mib() {
    let jabuti = Jabuti::novo(CofreMemoria::novo());
    let dados = Zeroizing::new(vec![0x5A; 12 * 1024 * 1024]);

    let registro = jabuti
        .proteger(
            "anexo-12m",
            CategoriaRegistro::Anexo,
            &dados,
            b"arquivo:teste.bin",
        )
        .expect("proteger 12 MiB");

    assert_eq!(registro.conteudo_cifrado.len(), dados.len() + 16);
    let aberto = jabuti.abrir(&registro).expect("abrir 12 MiB");
    assert_eq!(&*aberto, &*dados);
}

#[test]
fn rejeita_plaintext_acima_do_limite() {
    let config = ConfiguracaoJabuti {
        tamanho_maximo_plaintext: 8,
        ..ConfiguracaoJabuti::default()
    };
    let jabuti = Jabuti::com_configuracao(CofreMemoria::novo(), config);

    assert!(matches!(
        jabuti.proteger("grande", CategoriaRegistro::Mensagem, b"123456789", b""),
        Err(ErroJabuti::LimiteExcedido(_))
    ));
}

#[test]
fn serializa_e_reabre_registro() {
    let jabuti = Jabuti::novo(CofreMemoria::novo());
    let registro = jabuti
        .proteger(
            "serial",
            CategoriaRegistro::Mensagem,
            b"persistente",
            b"ctx",
        )
        .expect("proteger");

    let json = serde_json::to_vec(&registro).expect("json");
    let recarregado = serde_json::from_slice(&json).expect("desserializar");
    let aberto = jabuti.abrir(&recarregado).expect("abrir");
    assert_eq!(&*aberto, b"persistente");
}

#[test]
fn concorrencia_nao_reutiliza_chaves() {
    let jabuti = Arc::new(Jabuti::novo(CofreMemoria::novo()));
    let ids = Arc::new(Mutex::new(Vec::new()));
    let mut threads = Vec::new();

    for i in 0..32_u32 {
        let jabuti = Arc::clone(&jabuti);
        let ids = Arc::clone(&ids);
        threads.push(thread::spawn(move || {
            let registro = jabuti
                .proteger(
                    format!("msg-{i}"),
                    CategoriaRegistro::Mensagem,
                    format!("conteudo-{i}").as_bytes(),
                    b"concorrencia",
                )
                .expect("proteger");
            ids.lock()
                .expect("lock")
                .push(registro.id_chave.como_str().to_owned());
        }));
    }

    for t in threads {
        t.join().expect("thread");
    }

    let mut ids = ids.lock().expect("lock").clone();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 32);
}

struct CofreFalho {
    chave_existe: Mutex<bool>,
}

impl CofreFalho {
    fn novo() -> Self {
        Self {
            chave_existe: Mutex::new(false),
        }
    }
}

impl CofreDeChaves for CofreFalho {
    fn criar_chave(&self, _id: &IdChave) -> Resultado<()> {
        *self.chave_existe.lock().expect("lock") = true;
        Ok(())
    }

    fn cifrar(&self, _id: &IdChave, _plaintext: &[u8], _aad: &[u8]) -> Resultado<PacoteCifrado> {
        Err(ErroJabuti::FalhaCifragem)
    }

    fn decifrar(
        &self,
        _id: &IdChave,
        _pacote: &PacoteCifrado,
        _aad: &[u8],
    ) -> Resultado<Zeroizing<Vec<u8>>> {
        Err(ErroJabuti::FalhaDecifragem)
    }

    fn destruir_chave(&self, _id: &IdChave) -> Resultado<()> {
        *self.chave_existe.lock().expect("lock") = false;
        Ok(())
    }

    fn existe_chave(&self, _id: &IdChave) -> Resultado<bool> {
        Ok(*self.chave_existe.lock().expect("lock"))
    }

    fn nivel_protecao(&self) -> NivelProtecao {
        NivelProtecao::SoftwareTemporario
    }
}

#[test]
fn falha_de_cifragem_faz_rollback_da_chave() {
    let jabuti = Jabuti::novo(CofreFalho::novo());

    assert!(matches!(
        jabuti.proteger("falha", CategoriaRegistro::Mensagem, b"x", b""),
        Err(ErroJabuti::FalhaCifragem)
    ));

    let cofre = jabuti.cofre();
    assert!(!*cofre.chave_existe.lock().expect("lock"));
}
