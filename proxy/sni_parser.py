"""
Secure Forward Proxy - TLS SNI (Server Name Indication) Binary Parser
Parses RFC 5246 / RFC 6066 TLS ClientHello packets to extract destination
hostnames from HTTPS tunnels without decrypting end-to-end payload.
"""

import struct
from typing import Optional


def extract_sni_from_client_hello(data: bytes) -> Optional[str]:
    """
    Extracts the Server Name Indication (SNI) hostname from a raw TLS ClientHello handshake packet.
    Returns hostname string if found, otherwise None.
    """
    if len(data) < 5:
        return None

    # Check TLS Record header
    content_type, version, record_len = struct.unpack("!BHH", data[:5])
    if content_type != 0x16:  # 0x16 = TLS Handshake
        return None

    offset = 5
    if len(data) < offset + 4:
        return None

    # Check Handshake header
    handshake_type, = struct.unpack("!B", data[offset:offset + 1])
    if handshake_type != 0x01:  # 0x01 = ClientHello
        return None

    # Handshake length is 3 bytes (uint24)
    handshake_len = int.from_bytes(data[offset + 1:offset + 4], byteorder="big")
    offset += 4

    # Skip client_version (2 bytes) + random (32 bytes) = 34 bytes
    offset += 34
    if len(data) < offset + 1:
        return None

    # Skip session_id (1 byte length + data)
    session_id_len = data[offset]
    offset += 1 + session_id_len
    if len(data) < offset + 2:
        return None

    # Skip cipher_suites (2 bytes length + data)
    cipher_suites_len, = struct.unpack("!H", data[offset:offset + 2])
    offset += 2 + cipher_suites_len
    if len(data) < offset + 1:
        return None

    # Skip compression_methods (1 byte length + data)
    comp_methods_len = data[offset]
    offset += 1 + comp_methods_len
    if len(data) < offset + 2:
        return None

    # Extensions section length (2 bytes)
    extensions_len, = struct.unpack("!H", data[offset:offset + 2])
    offset += 2
    extensions_end = offset + extensions_len

    if len(data) < extensions_end:
        extensions_end = len(data)

    # Iterate through extensions to find server_name (0x0000)
    while offset + 4 <= extensions_end:
        ext_type, ext_len = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4

        if offset + ext_len > extensions_end:
            break

        if ext_type == 0x0000:  # server_name extension
            sni_offset = offset
            if sni_offset + 2 > offset + ext_len:
                break
            server_name_list_len, = struct.unpack("!H", data[sni_offset:sni_offset + 2])
            sni_offset += 2

            while sni_offset + 3 <= offset + ext_len:
                name_type, name_len = struct.unpack("!BH", data[sni_offset:sni_offset + 3])
                sni_offset += 3
                if sni_offset + name_len > offset + ext_len:
                    break
                if name_type == 0x00:  # host_name type
                    sni_bytes = data[sni_offset:sni_offset + name_len]
                    try:
                        return sni_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        return None
                sni_offset += name_len
            break

        offset += ext_len

    return None
