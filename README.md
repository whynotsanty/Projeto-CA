# FedFernet

Primeira fundacao do projeto de partilha federada de incidentes de seguranca.

## Estado atual

- `utils_crypto.py` gera e carrega chaves RSA-2048 e AES-256 em PEM/bytes.
- `fed_fernet.py` cria envelopes AES-GCM com `epoch` e AAD.
- A assinatura RSA e a identidade do membro ficam num cofre hibrido cifrado para
	o Arbiter (AES-GCM + RSA-OAEP).
- O `linkability_tag` e um HMAC deterministico por membro e `report_id`.
- `open()` abre o envelope sem revelar a identidade.
- `open_trace()` e a operacao reservada ao Arbiter e verifica a assinatura antes
	de devolver o membro identificado.

## Limitacao intencional

Isto e um simulador logico, nao uma implementacao real de group signatures.
Nesta fase, os membros ainda nao conseguem verificar anonimamente que uma
assinatura pertence a um membro valido sem conhecer a chave publica individual.
Essa sera a proxima camada do projeto, depois de estabilizar o formato do
envelope e os testes criptograficos.

## Exemplo de fluxo

```python
from fed_fernet import FedFernet
from utils_crypto import generate_aes_key, generate_rsa_key_pair

member_private, _ = generate_rsa_key_pair()
arbiter_private, arbiter_public = generate_rsa_key_pair()
federation_key = generate_aes_key()

token = FedFernet.seal(
		b'{"report_id":"r-1","incident_type":"ddos"}',
		federation_key,
		member_private,
		"member-a",
		arbiter_public,
		"r-1",
		b"tsa-token",
		epoch=0,
)
opened = FedFernet.open(token, federation_key)
member_id = FedFernet.open_trace(
		opened["trace_vault"], arbiter_private, opened["plaintext"]
)
```

Instalar dependencias:

```text
pip install -r requirements.txt
```
