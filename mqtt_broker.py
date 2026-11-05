"""Cliente MQTT com historico local para o protocolo da federacao."""

from __future__ import annotations

import base64
import json
import threading
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

import paho.mqtt.client as mqtt

from broker import BrokerMessage, LocalBroker


TOPIC_PREFIX = "fed/v1"
TOPIC_RELATORIOS = f"{TOPIC_PREFIX}/relatorios"
TOPIC_CORROBORACOES = f"{TOPIC_PREFIX}/corroboracoes"
TOPIC_DISPUTAS = f"{TOPIC_PREFIX}/disputas"


def topic_for(kind: str, report_id: str | None) -> str:
    """Converte um tipo de mensagem no topico MQTT correspondente."""
    if kind == "report":
        return TOPIC_RELATORIOS
    if kind == "corroboration" and report_id:
        return f"{TOPIC_CORROBORACOES}/{report_id}"
    if kind == "dispute" and report_id:
        return f"{TOPIC_DISPUTAS}/{report_id}"
    raise ValueError("tipo de mensagem ou report_id invalido")


def _wire_message(message: BrokerMessage) -> bytes:
    return json.dumps(message.to_dict(), sort_keys=True).encode("utf-8")


class MqttBrokerClient:
    """Implementa o contrato do broker sobre MQTT e um historico local."""

    def __init__(
        self,
        storage_path: str | Path,
        host: str,
        port: int = 1883,
        client_id: str | None = None,
        username: str | None = None,
        password: str | None = None,
        mqtt_client_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self._local_broker = LocalBroker(storage_path)
        self.host = host
        self.port = port
        self.client_id = client_id or f"fed-client-{uuid4()}"
        self._seen_message_ids: set[str] = set()
        factory = mqtt_client_factory or self._default_client_factory
        self._client = factory(self.client_id)
        if username is not None:
            self._client.username_pw_set(username, password)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._connected = False
        self._connection_event = threading.Event()
        self._connection_error: str | None = None

    @staticmethod
    def _default_client_factory(client_id: str) -> mqtt.Client:
        return mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
        )

    def connect(self, keepalive: int = 60) -> None:
        self._connection_event.clear()
        self._connection_error = None
        self._client.connect(self.host, self.port, keepalive)
        self._client.loop_start()
        if not self._connection_event.wait(timeout=10):
            raise ConnectionError("tempo excedido ao ligar ao broker MQTT")
        if self._connection_error is not None:
            raise ConnectionError(self._connection_error)

    def close(self) -> None:
        if self._connected:
            self._client.loop_stop()
            self._client.disconnect()
            self._connected = False

    def _on_connect(self, client: Any, _userdata: Any, _flags: Any, reason_code: Any, _properties: Any) -> None:
        if int(reason_code) != 0:
            self._connection_error = f"broker MQTT recusou a ligacao: {reason_code}"
            self._connection_event.set()
            return
        client.subscribe([(TOPIC_RELATORIOS, 1), (f"{TOPIC_CORROBORACOES}/#", 1), (f"{TOPIC_DISPUTAS}/#", 1)])
        self._connected = True
        self._connection_event.set()

    def _on_message(self, _client: Any, _userdata: Any, message: Any) -> None:
        try:
            value = json.loads(message.payload)
            message_id = str(value["message_id"])
            if message_id in self._seen_message_ids:
                return
            received = BrokerMessage.from_dict(value)
            self._local_broker.publish(
                received.payload,
                kind=received.kind,
                report_id=received.report_id,
                epoch=received.epoch,
            )
            self._seen_message_ids.add(message_id)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return

    def publish(
        self,
        payload: bytes,
        *,
        kind: str,
        report_id: str | None,
        epoch: int,
    ) -> BrokerMessage:
        if not self._connected:
            raise ConnectionError("cliente MQTT nao esta ligado")
        message = self._local_broker.publish(
            payload, kind=kind, report_id=report_id, epoch=epoch
        )
        self._seen_message_ids.add(message.message_id)
        result = self._client.publish(
            topic_for(kind, report_id), _wire_message(message), qos=1
        )
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise ConnectionError(f"falha ao publicar MQTT: {result.rc}")
        return message

    def pull(self, after_sequence: int = 0) -> list[BrokerMessage]:
        return self._local_broker.pull(after_sequence)

    @property
    def subscribed_topics(self) -> tuple[str, ...]:
        return (
            TOPIC_RELATORIOS,
            f"{TOPIC_CORROBORACOES}/#",
            f"{TOPIC_DISPUTAS}/#",
        )
