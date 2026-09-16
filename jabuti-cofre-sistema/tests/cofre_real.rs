use jabuti_cofre_sistema::CofreSistema;
use jabuti_core::{CategoriaRegistro, EstadoIntegridade, Jabuti};
use uuid::Uuid;

/// Teste destrutivo controlado no cofre real do SO.
///
/// Execute explicitamente:
///
/// JABUTI_TESTAR_COFRE_SISTEMA=1 \
/// cargo test -p jabuti-cofre-sistema --test cofre_real -- --ignored --nocapture
#[test]
#[ignore = "usa o cofre seguro real do sistema operacional"]
fn ciclo_real_do_cofre_do_sistema() {
    if std::env::var("JABUTI_TESTAR_COFRE_SISTEMA").as_deref() != Ok("1") {
        eprintln!("JABUTI_TESTAR_COFRE_SISTEMA != 1; teste não executado");
        return;
    }

    let namespace = format!("teste-{}", Uuid::new_v4());
    let cofre = CofreSistema::novo("org.jabuti.teste", namespace).expect("criar cofre nativo");
    cofre.diagnosticar().expect("diagnosticar");
    eprintln!("backend: {}", cofre.nome_backend());

    let jabuti = Jabuti::novo(cofre);
    let registro = jabuti
        .proteger(
            format!("registro-{}", Uuid::new_v4()),
            CategoriaRegistro::Mensagem,
            b"teste do cofre nativo",
            b"integracao",
        )
        .expect("proteger");

    let aberto = jabuti.abrir(&registro).expect("abrir");
    assert_eq!(&*aberto, b"teste do cofre nativo");
    drop(aberto);

    assert_eq!(
        jabuti
            .verificar_integridade(&registro)
            .expect("integridade"),
        EstadoIntegridade::Integro
    );

    jabuti.destruir(&registro).expect("destruir");
    assert_eq!(
        jabuti
            .verificar_integridade(&registro)
            .expect("integridade pós-delete"),
        EstadoIntegridade::ChaveAusente
    );
}
