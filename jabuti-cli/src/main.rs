use clap::{Parser, Subcommand};
use jabuti_cofre_sistema::CofreSistema;
use jabuti_core::{CategoriaRegistro, CofreMemoria, EstadoIntegridade, Jabuti};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "jabuti",
    version,
    about = "Ferramentas de diagnóstico e autoteste do Jabuti"
)]
struct Cli {
    #[command(subcommand)]
    comando: Comando,
}

#[derive(Subcommand)]
enum Comando {
    /// Testa o núcleo em memória sem persistir segredos.
    Autoteste,

    /// Testa o cofre nativo do sistema e remove a chave criada ao final.
    AutotesteSistema {
        #[arg(long, default_value = "org.jabuti.autoteste")]
        servico: String,
    },

    /// Exibe apenas o backend seguro selecionado e valida sua inicialização.
    DiagnosticoSistema {
        #[arg(long, default_value = "org.jabuti.diagnostico")]
        servico: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.comando {
        Comando::Autoteste => autoteste()?,
        Comando::AutotesteSistema { servico } => autoteste_sistema(&servico)?,
        Comando::DiagnosticoSistema { servico } => diagnostico_sistema(&servico)?,
    }

    Ok(())
}

fn autoteste() -> Result<(), Box<dyn std::error::Error>> {
    let jabuti = Jabuti::novo(CofreMemoria::novo());
    let plaintext = Zeroizing::new(b"autoteste-jabuti".to_vec());

    let registro = jabuti.proteger(
        format!("autoteste-{}", Uuid::new_v4()),
        CategoriaRegistro::Mensagem,
        &plaintext,
        b"cli-autoteste",
    )?;

    if registro
        .conteudo_cifrado
        .windows(plaintext.len())
        .any(|w| w == plaintext.as_slice())
    {
        return Err("plaintext apareceu no ciphertext".into());
    }

    let aberto = jabuti.abrir(&registro)?;
    if aberto.as_slice() != plaintext.as_slice() {
        return Err("round-trip divergente".into());
    }
    drop(aberto);

    if jabuti.verificar_integridade(&registro)? != EstadoIntegridade::Integro {
        return Err("integridade inesperada".into());
    }

    jabuti.destruir(&registro)?;
    if jabuti.verificar_integridade(&registro)? != EstadoIntegridade::ChaveAusente {
        return Err("chave permaneceu após crypto-shredding".into());
    }

    println!("Jabuti core: OK");
    Ok(())
}

fn autoteste_sistema(servico: &str) -> Result<(), Box<dyn std::error::Error>> {
    let namespace = format!("cli-autoteste-{}", Uuid::new_v4());
    let cofre = CofreSistema::novo(servico, namespace)?;
    cofre.diagnosticar()?;
    let backend = cofre.nome_backend();
    let jabuti = Jabuti::novo(cofre);

    let segredo = Zeroizing::new(b"autoteste-cofre-sistema".to_vec());
    let registro = jabuti.proteger(
        format!("registro-{}", Uuid::new_v4()),
        CategoriaRegistro::Mensagem,
        &segredo,
        b"cli-sistema",
    )?;

    let aberto = jabuti.abrir(&registro)?;
    if aberto.as_slice() != segredo.as_slice() {
        return Err("round-trip do cofre do sistema divergiu".into());
    }
    drop(aberto);

    jabuti.destruir(&registro)?;
    if jabuti.verificar_integridade(&registro)? != EstadoIntegridade::ChaveAusente {
        return Err("cofre do sistema manteve a chave após destruição".into());
    }

    println!("Jabuti cofre do sistema: OK ({backend})");
    Ok(())
}

fn diagnostico_sistema(servico: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cofre = CofreSistema::novo(servico, "diagnostico")?;
    cofre.diagnosticar()?;
    println!("backend: {}", cofre.nome_backend());
    println!("estado: disponível");
    Ok(())
}
