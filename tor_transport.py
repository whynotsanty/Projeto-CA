"""Transporte SOCKS5 para ligar o cliente Kafka a um daemon Tor real."""

from __future__ import annotations

import socket

import socks


class TorSocks5Transport:
    """Instala SOCKS5 no processo para que os sockets Kafka passem pelo Tor."""

    def __init__(self, proxy_host: str = "127.0.0.1", proxy_port: int = 9050) -> None:
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self._original_socket: object | None = None

    def install(self) -> None:
        if self._original_socket is not None:
            return
        self._original_socket = socket.socket
        socks.set_default_proxy(
            socks.SOCKS5,
            self.proxy_host,
            self.proxy_port,
            rdns=True,
        )
        socket.socket = socks.socksocket

    def close(self) -> None:
        if self._original_socket is None:
            return
        socket.socket = self._original_socket
        socks.set_default_proxy()
        self._original_socket = None