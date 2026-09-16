# Modelo de ameaças

## Objetivo

Proteger dados locais em repouso e tornar cópias residuais de ciphertext pouco
úteis após a destruição da chave individual correspondente.

## Ameaças contempladas

- SQLite/WAL/free pages contendo ciphertext antigo;
- SSD/flash com wear leveling;
- snapshots contendo ciphertext;
- registros lógicos excluídos mas fisicamente recuperáveis;
- adulteração de ciphertext/metadados;
- tentativa de usar um registro adulterado para destruir a chave de outro.

## Fora do escopo

- RAM adquirida com a aplicação aberta;
- endpoint comprometido enquanto a chave está acessível;
- root/jailbreak/admin suficiente para controlar o cofre do SO;
- exportações em claro;
- screenshots, clipboard e notificações;
- backups externos que incluam material de chave utilizável.

## Consequência para ferramentas forenses

Recuperar somente `RegistroCifrado` após a chave ter sido efetivamente destruída
não fornece ao Jabuti material suficiente para decifrá-lo. Isso melhora a
resistência a recuperação residual, mas não é uma promessa de derrota universal
de uma ferramenta forense: o resultado depende do estado do dispositivo,
backups, RAM, privilégios e segurança do cofre da plataforma.
