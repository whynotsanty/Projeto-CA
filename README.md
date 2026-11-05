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
- `broker.py`: broker local pull-based com armazenamento atomico em JSON.
- `broker_network.py`: servidor e cliente HTTP do broker, com suporte opcional
	para Tor.
- `federation_service.py`: publicacao, pull, corroboracao e disputas.
- `tsa.py`: TSA local verificavel para testes.
- `tor_transport.py`: transporte SOCKS5 para ligar clientes ao broker atraves
	de Tor (`127.0.0.1:9050` por defeito).

O estado do Coordinator recebe uma chave AES-256 separada no construtor. Essa
chave nao deve ser guardada no mesmo ficheiro JSON; deve ser fornecida pelo
ambiente seguro do processo do Coordinator. Os epochs ficam cifrados com
AES-GCM dentro do estado persistente.

O `TrustedTimestampAuthority` e uma TSA local verificavel para o prototipo.
Para uma implantacao real deve ser substituida por uma TSA RFC 3161 e a chave
publica da TSA deve ser configurada como confiavel. O `TorSocks5Transport`
requer um daemon Tor ativo; sem esse daemon, o broker HTTP funciona apenas por
ligacao direta para testes locais.

## Testes

```powershell
python -m pip install -r requirements.txt
python -m unittest -v
```

A suite cobre envelopes, adulteracao, chaves erradas, membros autorizados,
corroboracao unica, revogacao, rotacao de chaves, persistencia, TSA, pull
offline, broker HTTP e confidencialidade perante o broker.
