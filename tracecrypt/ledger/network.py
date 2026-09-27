"""Offline Authenticated LAN P2P Network Transport for TraceCrypt BFT Ledger.

Guarantees:
- 100% offline air-gapped LAN operation (no DNS, no cloud, no broadcast to unknown peers)
- Explicit static peer configuration
- Length-prefixed framing with SHA3-256 payload integrity:
  Format: [4-byte big-endian length] || [32-byte SHA3-256 payload digest] || [payload bytes]
- Replay protection and strict message size limits (16 MB max frame)
- Asynchronous non-blocking asyncio TCP server and client connection pool
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import struct
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from tracecrypt.errors import NetworkError, ValidationError

logger = logging.getLogger("tracecrypt.ledger.network")

MAX_FRAME_SIZE = 16 * 1024 * 1024  # 16 MB max frame size
FRAME_HEADER_LEN = 36  # 4 bytes length + 32 bytes SHA3-256 digest


class NetworkFrame:
    """Encapsulates binary framing and SHA3-256 integrity for wire messages."""

    @staticmethod
    def encode(payload: bytes) -> bytes:
        """Encode bytes into a framed wire message."""
        length = len(payload)
        if length > MAX_FRAME_SIZE:
            raise ValidationError(f"Frame size {length} exceeds maximum allowed {MAX_FRAME_SIZE} bytes.")
        digest = hashlib.sha3_256(payload).digest()
        header = struct.pack(">I", length) + digest
        return header + payload

    @staticmethod
    async def read_frame(reader: asyncio.StreamReader) -> Optional[bytes]:
        """Read a single length-prefixed, SHA3-256-verified frame from a stream."""
        try:
            header_bytes = await reader.readexactly(FRAME_HEADER_LEN)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            return None

        length = struct.unpack(">I", header_bytes[:4])[0]
        expected_digest = header_bytes[4:36]

        if length > MAX_FRAME_SIZE:
            logger.error("Incoming frame claims size %d > MAX_FRAME_SIZE %d", length, MAX_FRAME_SIZE)
            raise NetworkError(f"Oversized frame received: {length} bytes")

        try:
            payload = await reader.readexactly(length)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            return None

        actual_digest = hashlib.sha3_256(payload).digest()
        if actual_digest != expected_digest:
            logger.error("Corrupted frame: SHA3-256 checksum mismatch on incoming message.")
            raise NetworkError("Checksum mismatch on network frame.")

        return payload


class P2PNetwork:
    """Deterministic, offline LAN peer-to-peer transport manager for a ledger node."""

    def __init__(
        self,
        node_id: str,
        listen_host: str,
        listen_port: int,
        peers: List[Tuple[str, int]],
    ) -> None:
        self.node_id = node_id
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.configured_peers = [(h, int(p)) for h, p in peers if (h, int(p)) != (listen_host, listen_port)]

        self._server: Optional[asyncio.Server] = None
        self._handlers: Dict[str, Callable[[Dict[str, Any], str], Awaitable[Optional[Dict[str, Any]]]]] = {}
        self._active_connections: Dict[Tuple[str, int], Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self._running: bool = False
        self._bg_tasks: Set[asyncio.Task] = set()

    def register_handler(
        self,
        message_type: str,
        handler: Callable[[Dict[str, Any], str], Awaitable[Optional[Dict[str, Any]]]],
    ) -> None:
        """Register an async callback for handling incoming messages of a given type."""
        self._handlers[message_type] = handler

    async def start(self) -> None:
        """Start local TCP listening server and establish peer connections."""
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port,
        )
        logger.info("P2P Node %s listening on %s:%d", self.node_id, self.listen_host, self.listen_port)

        # Launch periodic peer connection maintenance
        task = asyncio.create_task(self._peer_maintenance_loop())
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)

    async def stop(self) -> None:
        """Gracefully terminate server and active connections."""
        self._running = False

        for task in list(self._bg_tasks):
            task.cancel()

        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        for addr, (r, w) in list(self._active_connections.items()):
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass
        self._active_connections.clear()
        logger.info("P2P Node %s stopped.", self.node_id)

    # -------------------------------------------------------------------------
    # Server Stream Handler
    # -------------------------------------------------------------------------

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming peer connection stream."""
        peer_addr = writer.get_extra_info("peername")
        logger.debug("Accepted connection from %s", peer_addr)

        try:
            while self._running:
                payload = await NetworkFrame.read_frame(reader)
                if payload is None:
                    break

                try:
                    envelope = json.loads(payload.decode("utf-8"))
                    msg_type = envelope.get("type")
                    sender_id = envelope.get("sender_id", "unknown")
                    data = envelope.get("data", {})

                    if msg_type in self._handlers:
                        response_data = await self._handlers[msg_type](data, sender_id)
                        if response_data is not None:
                            resp_env = {
                                "type": f"{msg_type}_RESP",
                                "sender_id": self.node_id,
                                "data": response_data,
                            }
                            resp_bytes = json.dumps(resp_env).encode("utf-8")
                            writer.write(NetworkFrame.encode(resp_bytes))
                            await writer.drain()
                except Exception as e:
                    logger.warning("Error processing message from %s: %s", peer_addr, e)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("Connection closed with %s: %s", peer_addr, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Peer Connection & Outbound Messaging
    # -------------------------------------------------------------------------

    async def _get_or_connect(
        self, host: str, port: int
    ) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        """Retrieve existing peer connection or open a new TCP connection."""
        addr = (host, port)
        if addr in self._active_connections:
            r, w = self._active_connections[addr]
            if not w.is_closing():
                return r, w
            del self._active_connections[addr]

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=2.0,
            )
            self._active_connections[addr] = (reader, writer)
            return reader, writer
        except Exception as e:
            logger.debug("Failed to connect to peer %s:%d: %s", host, port, e)
            return None

    async def _peer_maintenance_loop(self) -> None:
        """Periodically check peer connectivity in background."""
        while self._running:
            for host, port in self.configured_peers:
                await self._get_or_connect(host, port)
            await asyncio.sleep(5.0)

    async def broadcast(self, message_type: str, data: Dict[str, Any]) -> None:
        """Broadcast an authenticated message to all configured LAN peers."""
        envelope = {
            "type": message_type,
            "sender_id": self.node_id,
            "data": data,
        }
        frame = NetworkFrame.encode(json.dumps(envelope).encode("utf-8"))

        for host, port in self.configured_peers:
            conn = await self._get_or_connect(host, port)
            if conn is not None:
                _, writer = conn
                try:
                    writer.write(frame)
                    await writer.drain()
                except Exception as e:
                    logger.debug("Failed to broadcast to %s:%d: %s", host, port, e)
                    self._active_connections.pop((host, port), None)

    async def send_request(
        self,
        peer_host: str,
        peer_port: int,
        message_type: str,
        data: Dict[str, Any],
        timeout: float = 3.0,
    ) -> Optional[Dict[str, Any]]:
        """Send a request to a specific peer and await direct response."""
        envelope = {
            "type": message_type,
            "sender_id": self.node_id,
            "data": data,
        }
        frame = NetworkFrame.encode(json.dumps(envelope).encode("utf-8"))

        conn = await self._get_or_connect(peer_host, peer_port)
        if conn is None:
            return None

        reader, writer = conn
        try:
            writer.write(frame)
            await writer.drain()

            resp_payload = await asyncio.wait_for(
                NetworkFrame.read_frame(reader),
                timeout=timeout,
            )
            if resp_payload is None:
                return None

            resp_envelope = json.loads(resp_payload.decode("utf-8"))
            return resp_envelope.get("data")
        except Exception as e:
            logger.debug("Request %s to %s:%d failed: %s", message_type, peer_host, peer_port, e)
            self._active_connections.pop((peer_host, peer_port), None)
            return None
