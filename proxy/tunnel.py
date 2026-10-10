"""
Secure Forward Proxy - High-Performance Bidirectional TCP Tunnel
Pipes streaming TCP data between client and upstream destination with byte accounting.
"""

import asyncio
import logging
from typing import Tuple

logger = logging.getLogger("ProxyTunnel")


class TcpTunnel:
    def __init__(self, buffer_size: int = 65536, idle_timeout: float = 60.0):
        self.buffer_size = buffer_size
        self.idle_timeout = idle_timeout

    async def pipe(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        initial_client_data: bytes = b""
    ) -> Tuple[int, int]:
        """
        Bridges the client and upstream sockets concurrently.
        Returns (bytes_sent_by_client, bytes_sent_by_server).
        """
        bytes_client_to_server = len(initial_client_data)
        bytes_server_to_client = 0

        # If we pre-read some data (e.g. for SNI inspection), forward it first to the remote server
        if initial_client_data:
            try:
                remote_writer.write(initial_client_data)
                await remote_writer.drain()
            except Exception as e:
                logger.debug(f"Failed to flush initial data to remote: {e}")
                return bytes_client_to_server, 0

        async def _forward(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_client_to_remote: bool):
            nonlocal bytes_client_to_server, bytes_server_to_client
            try:
                while True:
                    data = await asyncio.wait_for(reader.read(self.buffer_size), timeout=self.idle_timeout)
                    if not data:
                        break  # EOF / socket closed normally
                    
                    writer.write(data)
                    await writer.drain()

                    if is_client_to_remote:
                        bytes_client_to_server += len(data)
                    else:
                        bytes_server_to_client += len(data)
            except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                pass
            except Exception as err:
                logger.debug(f"Tunnel forward error: {err}")
            finally:
                try:
                    if not writer.is_closing():
                        writer.close()
                except Exception:
                    pass

        # Run both directions concurrently until either disconnects or times out
        task_c2r = asyncio.create_task(_forward(client_reader, remote_writer, True))
        task_r2c = asyncio.create_task(_forward(remote_reader, client_writer, False))

        done, pending = await asyncio.wait(
            [task_c2r, task_r2c],
            return_when=asyncio.FIRST_COMPLETED
        )

        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        return bytes_client_to_server, bytes_server_to_client
