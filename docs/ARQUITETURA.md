# Arquitetura de produção

```text
App / Nheenga
    |
    | plaintext somente em RAM
    v
Jabuti Core
    |
    | cria id de chave único
    v
Cofre do Sistema ------------------------+
    |                                    |
    | chave de 256 bits                  |
    |                                    |
    +--> AES-256-GCM <---- AAD ----------+
             |
             v
       RegistroCifrado
             |
             v
      banco/arquivo local
```

Cada registro possui sua própria chave. O ciphertext e os metadados necessários
podem sobreviver fisicamente à exclusão; a propriedade de crypto-shredding vem
da destruição da chave correspondente no cofre seguro.

## Separação de domínios

O AAD inclui `JABUTI-REGISTRO-AEAD-V1`, versão, algoritmo, ID do registro, ID da
chave, categoria e contexto extra. Mover o ciphertext entre registros ou alterar
esses metadados invalida a autenticação GCM.

## Identificadores no cofre

O cofre nativo não recebe o ID lógico bruto como nome da credencial. Jabuti usa
SHA-256 sobre `namespace + id_chave` e guarda a credencial como `v1-<hash>`.
Isso reduz vazamento de identificadores de conversa/mensagem na UI do keyring.

## Multiaplicativo

Cada aplicativo deve usar `servico` exclusivo, por exemplo:

```text
br.mpma.nheenga.jabuti
br.mpma.outrochat.jabuti
```

E cada perfil/dispositivo deve fornecer um `namespace` estável e não secreto.
