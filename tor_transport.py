"""Minimal SOCKS5 transport for routing broker connections through Tor."""

from __future__ import annotations

import socket
import struct


class TorSocks5Transport:
    """Open TCP connections through a local Tor SOCKS5 proxy."""

    def __init__(self, proxy_host: str = "127.0.0.1", proxy_port: int = 9050) -> None:
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def connect(self, target_host: str, target_port: int, timeout: float = 10.0) -> socket.socket:
        connection = socket.create_connection(
            (self.proxy_host, self.proxy_port), timeout=timeout
        )
        try:
            connection.sendall(b"\x05\x01\x00")
            version, method = connection.recv(2)
            if (version, method) != (5, 0):
                raise ConnectionError("Tor SOCKS5 proxy rejected unauthenticated mode")
            host = target_host.encode("idna")
            if len(host) > 255:
                raise ValueError("target hostname is too long")
            request = b"\x05\x01\x00\x03" + bytes([len(host)]) + host
            request += struct.pack("!H", target_port)
            connection.sendall(request)
            response = connection.recv(4)
            if len(response) != 4 or response[0] != 5 or response[1] != 0:
                raise ConnectionError("Tor SOCKS5 connection failed")
            address_type = response[3]
            if address_type == 1:
                connection.recv(4)
            elif address_type == 3:
                length = connection.recv(1)[0]
                connection.recv(length)
            elif address_type == 4:
                connection.recv(16)
            else:
                raise ConnectionError("invalid SOCKS5 address type")
            connection.recv(2)
            return connection
        except Exception:
            connection.close()
            raise
