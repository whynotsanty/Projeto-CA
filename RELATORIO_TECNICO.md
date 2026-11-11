# Relatorio tecnico

## 1. Objetivo

Este documento regista as decisoes tecnicas, as implementacoes realizadas, os
ensaios executados e as limitacoes conhecidas da plataforma de partilha
confidencial de incidentes entre membros de uma federacao.

O objetivo nao e afirmar que o prototipo e uma implementacao profissional de
cada primitiva academica. O objetivo e demonstrar uma arquitetura coerente,
usar primitivas criptograficas existentes e explicar honestamente quais
propriedades sao garantidas, quais sao aproximadas e quais dependem da
infraestrutura externa.

## 2. Estado atual da implementacao

### 2.1 Modelo de incidentes

O modulo `models.py` implementa `IncidentReport` e valida:

- `report_id` como UUID;
- tipos de incidente permitidos;
- severidades permitidas;
- mitigacoes permitidas;
- os quatro campos obrigatorios de `indicators`;
- periodo de observacao com duracao positiva;
- timestamps com timezone e normalizacao para UTC;
- serializacao JSON canonica.

O plaintext do relatorio mantem a estrutura exigida pelo enunciado.

### 2.2 Criptografia

O modulo `utils_crypto.py` usa a biblioteca `cryptography` para as operacoes
criptograficas de baixo nivel:

- RSA-2048 ou superior para chaves de membros e do Arbiter;
- RSA-PSS com SHA-256 para assinaturas;
- RSA-OAEP com SHA-256 para proteger a chave do `trace_vault`;
- AES-256-GCM para confidencialidade e integridade;
- PEM para serializacao das chaves.

Nao foram implementadas primitivas criptograficas manualmente.

### 2.3 FedFernet

O modulo `fed_fernet.py` organiza a receita criptografica da aplicacao numa
classe `FedFernet`, com os metodos principais `seal`, `open` e `open_trace`.

Cada envelope inclui:

- payload cifrado com AES-256-GCM;
- epoch da chave da federacao;
- identificador do relatorio;
- assinatura do membro;
- `trace_vault` cifrado para o Arbiter;
- `linkability_tag` deterministico;
- token da TSA.

A assinatura inclui agora o `report_id` como contexto canonico. Isto impede
que uma assinatura valida para um contexto seja reutilizada noutro contexto.

O `trace_vault` contem a identidade, a chave publica e a assinatura do autor.
A chave do cofre e protegida com RSA-OAEP e o conteudo e protegido com
AES-GCM. Apenas o Arbiter com a chave privada adequada consegue abrir o cofre.

### 2.4 Coordinator

O modulo `coordinator.py` gere:

- registo de membros;
- chaves publicas dos membros;
- revogacao;
- lista de revogacoes;
- epochs de chaves da federacao;
- persistencia cifrada do estado;
- rotacao de chaves apos revogacao.

A chave que protege o estado do Coordinator nao e guardada dentro do ficheiro
JSON. O estado inclui os epochs cifrados com AES-256-GCM.

Como defesa em profundidade, o Coordinator pode receber um
`KafkaAccessController`. Durante a revogacao, este remove as ACLs do principal
`User:<member_id>` nos topicos Kafka da aplicacao.

### 2.5 Kafka

O modulo `kafka_broker.py` e o unico adaptador de broker do projeto.
Implementa:

- publicacao de relatorios, corroboracoes e disputas;
- consumo pull-based por offset;
- replay de mensagens para membros offline;
- topicos de controlo para revogacoes e epochs;
- validacao dos tipos de mensagem;
- remocao de ACLs Kafka de membros revogados.

Topicos utilizados:

```text
fed.v1.events
fed.v1.coordinator.revocations
fed.v1.coordinator.epochs
```

O topico de eventos deve ter uma particao para que o offset possa ser usado
como sequencia global.

Os brokers local/JSON, HTTP e MQTT foram removidos para manter uma unica
implementacao de transporte.

### 2.6 Tor

O modulo `tor_transport.py` usa `PySocks` para instalar um transporte SOCKS5
real no processo. A resolucao DNS e feita remotamente pelo Tor (`rdns=True`).

O cliente Kafka pode receber um `TorSocks5Transport` antes de criar produtor e
consumidor, fazendo com que os sockets Kafka sejam criados atraves do daemon
Tor.

Esta integracao exige um daemon Tor real ativo e um endpoint Kafka alcancavel
pela rede Tor. O uso de `localhost:9092` nao e suficiente para demonstrar um
fluxo anonimizado real.

### 2.7 TSA

O modulo `tsa.py` implementa uma TSA local propria, baseada nos campos
essenciais do RFC 3161:

- `message_imprint`;
- algoritmo SHA-256;
- hash do payload;
- politica OID;
- numero de serie;
- nonce;
- `gen_time`;
- estado `granted`;
- assinatura RSA da TSA.

O token e transportado em JSON para manter o prototipo simples. Nao e uma
mensagem ASN.1/DER completa e, portanto, nao deve ser descrito como uma
implementacao RFC 3161 totalmente interoperavel. E uma TSA local inspirada no
padrao, com verificacao de autenticidade, integridade e data de emissao.

## 3. Group signatures

### 3.1 O que esta implementado

A classe `FederationGroup` e o metodo `FedFernet.verify_group_signature`
implementam uma simulacao controlada:

1. um membro assina com RSA-PSS;
2. o verificador testa a assinatura contra as chaves publicas autorizadas;
3. o resultado normal e apenas valido/invalido;
4. o `trace_vault` permite ao Arbiter abrir a identidade quando autorizado.

A implementacao usa uma abstracao limpa (`FedFernet`) e a biblioteca
`cryptography`, em vez de reimplementar RSA, AES ou HMAC.

### 3.2 O que esta simulacao garante

Dentro do fluxo da aplicacao, a simulacao garante:

- autenticidade criptografica de que uma chave registada assinou;
- integridade do conteudo assinado;
- rejeicao de assinaturas de chaves desconhecidas;
- possibilidade de o Arbiter revelar o autor;
- impossibilidade de o autor negar a assinatura quando o Arbiter abre e
  verifica o cofre;
- linkability controlada por relatorio atraves do `linkability_tag`;
- rejeicao de autocorroboracao;
- rejeicao de corroboracao duplicada pelo mesmo membro no mesmo relatorio.

### 3.3 O que ela nao garante

Isto nao e uma group signature formal com anonimato criptografico forte.
Como a assinatura RSA e verificavel contra a lista de chaves publicas, um
membro que tenha essa lista pode testar cada chave separadamente e descobrir
qual membro assinou.

Consequentemente, a implementacao atual nao garante, a 100%:

- anonimato forte do assinante perante membros que conhecem todas as chaves;
- unlinkability plena entre relatorios;
- a propriedade formal de uma construcao BBS/BBS+ ou equivalente.

A propriedade correta a reclamar e: simulacao de group signatures com
anonimato de interface e tracing por cofre, mas com risco de identificacao por
verificacao individual das chaves.

### 3.4 Tentativa de usar uma biblioteca real

Foi investigada a biblioteca `pygroupsig` 1.1.0. O teste mostrou:

- o pacote existe no indice Python;
- a instalacao falha no Python 3.14 durante o build;
- a falha inicial referia a dependencia antiga `path`;
- depois de instalar `path`, o build falhou novamente com
  `Cannot import setuptools.build_meta`;
- nao foi encontrada uma alternativa Python simples e estavel no ambiente.

A biblioteca nao foi adicionada ao projeto. Isto e preferivel a implementar
uma construcao criptografica academica manual sem garantias.

## 4. Testes realizados e resultados

### 4.1 Analise estatica

Foi executada a analise do workspace nos modulos alterados, incluindo:

- `fed_fernet.py`;
- `federation_service.py`;
- `coordinator.py`;
- `kafka_broker.py`;
- `tor_transport.py`;
- `tsa.py`;
- `test_protocol.py`;
- `test_fed_fernet.py`;
- `README.md`.

Resultado: nenhum diagnostico estatico encontrado.

### 4.2 Testes unitarios preparados

Os testes em `test_fed_fernet.py` cobrem:

- round-trip do envelope;
- verificacao de assinatura;
- tracing pelo Arbiter;
- membro desconhecido;
- membros registados;
- adulteracao;
- chave da federacao errada;
- chave do Arbiter errada;
- plaintext alterado;
- inputs invalidos.

Os testes em `test_protocol.py` cobrem:

- publicacao e pull de relatorios;
- confidencialidade perante o broker;
- corroboracao unica;
- autocorroboracao;
- tracing de disputas;
- replay de timestamp;
- revogacao e rotacao de epoch;
- persistencia do Coordinator;
- campos RFC-inspired da TSA;
- replay Kafka por offset;
- tipos de mensagem invalidos;
- restricao de topicos de controlo;
- remocao de ACL Kafka na revogacao.

Os testes foram atualizados depois da introducao do contexto na assinatura.
A suite completa nao foi executada pelo interpretador local porque o workspace
esta exposto como `vscode-vfs` e nao esta montado como diretorio no filesystem
do Python.

### 4.3 Kafka

Foi instalada a dependencia `kafka-python`. O cliente Kafka conseguiu
inicializar contra `localhost:9092`, mas o smoke test completo de produzir e
consumir num topico temporario expirou. O cluster deve ter os topicos criados
explicitamente e configurados antes de repetir o teste.

A API de ACL do `kafka-python 3.0.13` foi testada. Foi necessario usar
`ACLResourcePatternType` e `ResourcePattern`, pois a API nao exporta
`ResourcePatternType` nem aceita `ResourceType.ANY` no filtro.

### 4.4 Tor

Foi executado um teste SOCKS5 real para `127.0.0.1:9050` contra
`check.torproject.org`.

Resultado: falhou com `ConnectionRefusedError`, porque nao havia um daemon Tor
ativo a escutar nessa porta. A falha demonstra que o teste tentou contactar
um proxy real, nao um mock. O teste deve ser repetido depois de instalar e
iniciar o Tor.

### 4.5 Biblioteca de group signatures

O teste de `pygroupsig` falhou no build conforme descrito na secao 3.4. A
biblioteca foi removida do ambiente experimental e nao foi adicionada ao
`requirements.txt`.

## 5. Confronto com o enunciado

### 5.1 Requisitos cobertos

| Requisito | Estado | Justificacao |
|---|---|---|
| Registo de membros | Implementado | Coordinator regista IDs e chaves publicas. |
| Revogacao | Implementado | CRL interna, epoch novo e bloqueio de publicacao. |
| Formato do relatorio | Implementado | `IncidentReport` valida e serializa o JSON pedido. |
| Distribuicao a todos | Implementado no desenho | Kafka usa topico comum de eventos. |
| Membros offline | Implementado no desenho | Log Kafka e offsets permitem replay. |
| Confidencialidade | Implementado | AES-256-GCM cifra os envelopes. |
| Integridade | Implementado | GCM e RSA-PSS detetam adulteracoes. |
| Autenticidade | Parcialmente implementado | RSA-PSS prova uma chave registada, mas a simulacao nao e group signature formal. |
| Timestamping | Implementado localmente | TSA assina hash e tempo; formato JSON nao e DER RFC 3161. |
| Accountability | Implementado | Arbiter abre `trace_vault` e verifica a assinatura. |
| Corroboracao unica | Implementado | `linkability_tag` e verificacao de duplicados. |
| Nao autocorroboracao | Implementado | Tag propria e comparada antes de publicar. |
| ACL Kafka | Implementado como defesa adicional | Remocao por principal nos topicos da aplicacao. |
| Tor | Integracao implementada | Depende de daemon Tor real e endpoint alcancavel. |

### 5.2 Requisitos ainda nao garantidos a 100%

#### Anonimato

O conteudo fica cifrado perante o broker e a identidade nao aparece no
payload publico. Contudo, a simulacao RSA permite identificar o assinante se
um participante testar a assinatura contra cada chave publica.

A rede tambem pode revelar metadados. Sem Tor, o broker pode observar o
endereco IP do membro. Mesmo com Tor, padroes de tempo, volume e ligacao podem
produzir analise de trafego.

#### Unlinkability

A escolha atual e unlinkability flexivel por relatorio:

- tags iguais para o mesmo membro e relatorio permitem bloquear duplicados;
- tags de relatorios diferentes nao sao diretamente comparaveis;
- a assinatura RSA e uma fonte residual de linkability para quem testar as
  chaves publicas;
- o tracing de um relatorio pode revelar o autor daquele relatorio e, devido
  a metadados externos, permitir correlacoes adicionais.

#### Revogacao retroativa

A rotacao de epoch impede o acesso a novos relatorios. Nao pode apagar um
plaintext ou uma chave que o membro revogado ja tenha obtido. As ACLs Kafka
impedem novas ligacoes, mas nao retiram dados ja consumidos.

#### Infraestrutura real

O codigo tem adaptadores Kafka e Tor, mas a demonstracao completa exige:

- cluster Kafka real;
- topicos criados;
- autenticacao TLS/SASL e principals individuais;
- daemon Tor real;
- endpoint Kafka alcancavel pelo Tor;
- teste de dois ou mais membros.

## 6. Comparacao de alternativas

### Broker

Kafka foi escolhido por ser uma infraestrutura existente, testada e adequada
a logs duraveis, offsets, replay e consumidores offline. Um broker local ou
MQTT seria mais simples em alguns cenarios, mas foram removidos para evitar
implementacoes concorrentes no projeto.

### Criptografia autenticada

AES-GCM foi escolhido em vez de AES-CBC com HMAC separado porque fornece
confidencialidade e autenticidade numa API autenticada moderna. CBC+HMAC seria
possivel, mas aumenta o risco de erros de composicao.

### Assinaturas de grupo

Uma group signature formal teria anonimato mais forte e tracing nativo, mas
exige uma biblioteca academica compativel ou uma implementacao especializada.
A simulacao RSA foi escolhida porque e verificavel, compreensivel e segura ao
nivel das primitivas, embora nao forneca a mesma propriedade de anonimato.

### TSA

Uma TSA RFC 3161 externa ofereceria interoperabilidade. A TSA propria foi
escolhida porque pode ficar dentro da CA e permite demonstrar hash, timestamp,
nonce, numero de serie e assinatura. A limitacao JSON versus ASN.1/DER deve ser
explicitada.

## 7. Conclusao para a defesa

A formulacao tecnicamente correta e:

> O projeto implementa uma plataforma de partilha confidencial baseada em
> AES-GCM, RSA-PSS, RSA-OAEP, uma TSA local inspirada no RFC 3161, Kafka e Tor.
> O FedFernet organiza essas primitivas num envelope proprio. A camada de
> group signatures e uma simulacao controlada baseada em RSA-PSS, suficiente
> para demonstrar autenticidade, tracing e linkability por relatorio, mas nao
> equivalente a uma construcao formal de group signatures com anonimato
> criptografico forte.

Esta formulacao e mais defensavel do que afirmar que a simulacao garante todas
as propriedades de uma group signature formal.

## 8. Passos seguintes recomendados

1. Instalar e iniciar um daemon Tor real.
2. Criar os tres topicos Kafka com uma particao no topico de eventos.
3. Configurar principals Kafka individuais e ACLs.
4. Executar a suite Python a partir de um checkout local real do repositorio.
5. Executar um teste integrado com dois membros, Kafka, Tor e revogacao.
6. Escrever o relatorio academico final com as alternativas e limitacoes
   acima, respeitando o limite de dez paginas do enunciado.
