# FedFernet

Plataforma de partilha confidencial de incidentes de seguranca entre membros
de uma federacao. Esta implementacao e um prototipo executavel para o projeto
de Criptografia Aplicada.

## Arquitetura

```text
Membro -> Tor/SOCKS5 -> Broker -> todos os membros ativos
												 |
												 +-- historico pull-based

Coordinator: membros, revogacao, epochs e chaves AES da federacao
TSA: tokens de timestamp assinados
Arbiter: abre o trace_vault apenas em disputas autorizadas
```

O broker guarda apenas tokens `FedFernet` cifrados. Nao consegue ler o
relatorio, a identidade, a assinatura ou o conteudo das corroboracoes.

## Formato do relatorio

O plaintext segue o formato exigido pelo enunciado:

```json
{
	"report_id": "3f1c2a9e-7b4d-4e8a-9c21-5d6f0a1b2c3d",
	"incident_type": "ddos",
	"indicators": {
		"source_prefixes": ["203.0.113.0/24"],
		"source_asns": [64500],
		"destination_ports": [53],
		"protocols": ["udp"]
	},
	"observation_period": {
		"start": "2026-11-20T14:05:00Z",
		"end": "2026-11-20T14:47:00Z"
	},
	"severity": "high",
	"recommended_mitigation": "rate_limiting"
}
```

`models.py` valida UUID, campos obrigatorios, valores permitidos e timestamps
UTC ISO 8601 antes de qualquer publicacao.

## Criptografia

- AES-256-GCM protege cada envelope e fornece confidencialidade e integridade.
- RSA-PSS assina o plaintext do relatorio.
- A simulacao de group signatures testa a assinatura contra as chaves dos
	membros sem revelar qual chave correspondeu.
- RSA-OAEP protege a chave do `trace_vault` para o Arbiter.
- O `linkability_tag` e deterministico por membro e por relatorio, permitindo
	impedir autocorroboracao e corroboracao duplicada sem expor o membro.
- `TrustedTimestampAuthority` assina tokens ligados ao hash do relatorio e
	permite verificar o timestamp.

Esta e uma simulacao simples de group signatures, nao uma construcao academica
completa. Essa limitacao e deliberada e deve ser discutida no relatorio.

## Componentes

- `models.py`: modelo JSON validado dos incidentes.
- `fed_fernet.py`: envelope cifrado, assinatura e trace do Arbiter.
- `coordinator.py`: registo, revogacao, persistencia e rotacao de epochs.
- `kafka_broker.py`: adaptador Kafka com log duravel, offsets e replay para
	membros que estiveram offline, incluindo remocao de ACLs na revogacao.
- `tor_transport.py`: transporte SOCKS5 para ligar Kafka atraves de um daemon
	Tor real.
- `federation_service.py`: publicacao, pull, corroboracao e disputas.
- `tsa.py`: TSA local verificavel para testes.

O estado do Coordinator recebe uma chave AES-256 separada no construtor. Essa
chave nao deve ser guardada no mesmo ficheiro JSON; deve ser fornecida pelo
ambiente seguro do processo do Coordinator. Os epochs ficam cifrados com
AES-GCM dentro do estado persistente.

O `TrustedTimestampAuthority` e uma TSA local verificavel baseada nos campos
essenciais do RFC 3161: `messageImprint`, SHA-256, politica, numero de serie,
nonce, `genTime`, estado `granted` e assinatura da TSA. O token e transportado
em JSON para manter o prototipo simples; nao e uma implementacao DER completa
de `TimeStampResp`. Para uma implantacao real, a mesma interface deve ser
ligada a uma TSA RFC 3161 externa ou substituida por uma resposta ASN.1 DER.

## Transporte Kafka

Kafka e o transporte principal da arquitetura. `FederationService` depende
apenas do contrato `BrokerInterface`, com `publish()` e `pull()`, por isso a
criptografia nao depende da implementacao concreta do broker. O offset Kafka
e usado como `sequence`, permitindo recuperar mensagens depois de uma
desconexao sem criar um broker proprio. O topico `fed.v1.events` deve ser
criado com uma particao para manter o `sequence` global baseado no offset.

Antes de iniciar os membros, crie os topicos explicitamente no cluster:

```powershell
kafka-topics --bootstrap-server localhost:9092 --create --if-not-exists --topic fed.v1.events --partitions 1 --replication-factor 1
kafka-topics --bootstrap-server localhost:9092 --create --if-not-exists --topic fed.v1.coordinator.revocations --partitions 1 --replication-factor 1
kafka-topics --bootstrap-server localhost:9092 --create --if-not-exists --topic fed.v1.coordinator.epochs --partitions 1 --replication-factor 1
```

Os topicos Kafka sao:

```text
fed.v1.events
fed.v1.coordinator.revocations
fed.v1.coordinator.epochs
```

Os membros publicam relatorios, corroboracoes e disputas em `fed.v1.events`;
o Coordinator publica revogacoes e epochs nos topicos de controlo. O payload
Kafka e sempre um token FedFernet cifrado.

## Revogacao no Kafka

Como defesa em profundidade, o Coordinator pode receber um
`KafkaAccessController` configurado com as credenciais administrativas do
cluster. Ao revogar `member-a`, ele remove as ACLs do principal
`User:member-a`. O Kafka deve estar configurado com autenticacao TLS ou SASL
e cada membro deve usar um principal proprio. A rotacao do epoch continua a
ser a protecao criptografica principal; a ACL impede que o membro revogado
continue a publicar ou consumir atraves da infraestrutura.

Quando o requisito de anonimato estiver ativo, crie o cliente com
`TorSocks5Transport` e passe-o para `KafkaBrokerClient`. O adaptador instala
SOCKS5 no processo com `rdns=True`, por isso o destino e resolvido pelo Tor e
nao pelo DNS local. O daemon Tor deve estar ativo (por defeito em
`127.0.0.1:9050`) e o endereco Kafka deve ser alcancavel atraves da rede Tor.
O teste de demonstracao deve abrir uma ligacao SOCKS5 real e depois executar o
fluxo Kafka usando esse transporte; uma simulacao nao satisfaz este requisito.

## Testes

```powershell
python -m pip install -r requirements.txt
python -m unittest -v
```

A suite cobre envelopes, adulteracao, chaves erradas, membros autorizados,
corroboracao unica, revogacao, rotacao de chaves, persistencia, TSA, pull
offline, Kafka e confidencialidade perante o broker.
