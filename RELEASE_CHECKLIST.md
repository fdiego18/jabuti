# Checklist de release de produção

Antes de liberar Jabuti em um app:

- [ ] `./scripts/testar-producao.sh` passa sem warnings;
- [ ] `cargo audit` sem advisory não aceito;
- [ ] `cargo deny check` revisado;
- [ ] teste real do cofre executado com `JABUTI_TESTAR_COFRE_SISTEMA=1`;
- [ ] app não grava plaintext em SQLite/WAL/log/cache;
- [ ] app não põe plaintext em `contexto_extra`;
- [ ] previews/índices são cifrados ou removidos;
- [ ] clipboard/notificações seguem política do produto;
- [ ] tombstone multi-dispositivo testado;
- [ ] backup/restauração não ressuscita chave excluída;
- [ ] exclusão de anexo limpa cópias privadas controladas pelo app;
- [ ] arquivos exportados são explicitamente tratados como fora do domínio Jabuti;
- [ ] Android/iOS testados em dispositivo físico;
- [ ] Linux testado com o Secret Service usado na distribuição alvo;
- [ ] Windows/macOS testados em conta de usuário real;
- [ ] revisão de segurança independente realizada antes de alegações forenses fortes.
