"""Broker e cliente HTTP; a carga continua a ser um token FedFernet opaco."""

from __future__ import annotations

import base64
import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from broker import BrokerMessage, LocalBroker
from tor_transport import TorSocks5Transport


class BrokerHttpServer:
    """Expoe o LocalBroker atraves de uma API HTTP pequena."""

    def __init__(self, storage_path: str, host: str = "127.0.0.1", port: int = 0) -> None:
        broker = LocalBroker(storage_path)

        class RequestHandler(BaseHTTPRequestHandler):
            def _respond(self, status: int, value: object) -> None:
                payload = json.dumps(value, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:
                if self.path != "/publish":
                    self._respond(404, {"error": "rota desconhecida"})
                    return
                try:
                    length = int(self.headers["Content-Length"])
                    value = json.loads(self.rfile.read(length))
                    payload = base64.urlsafe_b64decode(value["payload"].encode("ascii"))
                    message = broker.publish(
                        payload,
                        kind=value["kind"],
                        report_id=value.get("report_id"),
                        epoch=int(value["epoch"]),
                    )
                    self._respond(201, message.to_dict())
                except (KeyError, TypeError, ValueError) as exc:
                    self._respond(400, {"error": str(exc)})

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path != "/pull":
                    self._respond(404, {"error": "rota desconhecida"})
                    return
                try:
                    after = int(parse_qs(parsed.query).get("after", ["0"])[0])
                    self._respond(200, [message.to_dict() for message in broker.pull(after)])
                except ValueError as exc:
                    self._respond(400, {"error": str(exc)})

            def log_message(self, *_args: object) -> None:
                return

        self.server = ThreadingHTTPServer((host, port), RequestHandler)
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self.server.server_address

    def start(self) -> None:
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)


class BrokerHttpClient:
    """Cliente HTTP com encaminhamento SOCKS5/Tor opcional."""

    def __init__(
        self,
        host: str,
        port: int,
        transport: TorSocks5Transport | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.transport = transport

    def _request(self, method: str, path: str, body: bytes | None = None) -> object:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if self.transport is None:
            connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            status = response.status
            connection.close()
        else:
            socket = self.transport.connect(self.host, self.port)
            request = f"{method} {path} HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n"
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"
            if body is not None:
                request += f"Content-Length: {len(body)}\r\n"
            request += "\r\n"
            socket.sendall(request.encode("ascii") + (body or b""))
            response = http.client.HTTPResponse(socket)
            response.begin()
            payload = response.read()
            status = response.status
            socket.close()
        if status >= 400:
            raise ConnectionError(payload.decode("utf-8", errors="replace"))
        return json.loads(payload)

    def publish(
        self,
        payload: bytes,
        *,
        kind: str,
        report_id: str | None,
        epoch: int,
    ) -> BrokerMessage:
        value = self._request(
            "POST",
            "/publish",
            json.dumps(
                {
                    "payload": base64.urlsafe_b64encode(payload).decode("ascii"),
                    "kind": kind,
                    "report_id": report_id,
                    "epoch": epoch,
                }
            ).encode("utf-8"),
        )
        return BrokerMessage.from_dict(value)

    def pull(self, after_sequence: int = 0) -> list[BrokerMessage]:
        value = self._request("GET", f"/pull?after={after_sequence}")
        return [BrokerMessage.from_dict(item) for item in value]
