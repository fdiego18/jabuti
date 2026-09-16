# Segurança do Jabuti

## Primitivas

- AES-256-GCM;
- chave aleatória de 256 bits por registro;
- nonce aleatório de 96 bits por cifragem;
- AAD com separação de domínio e metadados imutáveis;
- SHA-256 do ciphertext para detecção rápida de corrupção antes da AEAD;
- `Zeroizing` para plaintext retornado e material de chave temporariamente carregado;
- nenhuma implementação criptográfica própria.

## Exclusão

`Jabuti::destruir()` autentica o registro antes de apagar uma chave existente.
Isso evita um ataque em que um registro adulterado troque `id_chave` pelo ID de
outra mensagem para apagar a chave errada.

A destruição é idempotente. Depois de o cofre confirmar a remoção, a aplicação
deve remover ciphertext, preview, índice, caches e emitir tombstone quando
existirem outros dispositivos.

## Cofre do sistema

`jabuti-cofre-sistema` usa o mecanismo nativo da plataforma. A chave individual
é codificada em Base64 apenas para compatibilidade uniforme com stores que
aceitam texto, e o buffer temporário é zeroizado.

O nível `CofreDoSistema` não equivale automaticamente a `Hardware`. Hardware
backing depende do dispositivo e do backend.

## O Jabuti não promete

O Jabuti não impede:

- coleta de RAM enquanto plaintext ou chave estão em uso;
- comprometimento com root/jailbreak/admin suficiente;
- captura de tela, clipboard, notificações ou acessibilidade maliciosa;
- recuperação de uma cópia exportada para Downloads/nuvem/outro aplicativo;
- backups que preservem material de chave recuperável;
- falhas do próprio cofre seguro do SO.

Por isso não há garantia absoluta contra Cellebrite, GrayKey ou ferramenta
forense equivalente. O objetivo é reduzir fortemente a utilidade de dados
residuais recuperados do armazenamento depois da destruição real da chave.

## Regras de integração

1. plaintext nunca deve ser persistido antes do Jabuti;
2. não logar plaintext/chaves;
3. não usar `contexto_extra` para segredos;
4. limpar previews, índices, clipboard e caches;
5. revisar backups do SO;
6. propagar tombstones em multi-dispositivo;
7. arquivos exportados para Downloads deixam o domínio de proteção do Jabuti;
8. validar o cofre nativo em cada plataforma real;
9. revisar dependências com `cargo audit`/`cargo deny`;
10. realizar auditoria externa antes de alegações de alta resistência forense.
