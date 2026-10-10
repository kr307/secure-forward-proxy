"""
Unit tests for binary TLS ClientHello SNI parser.
"""

import struct
import pytest
from proxy.sni_parser import extract_sni_from_client_hello


def build_synthetic_client_hello(sni_hostname: str) -> bytes:
    """Helper to craft an RFC-compliant TLS 1.2 ClientHello binary packet containing SNI extension."""
    sni_bytes = sni_hostname.encode("utf-8")
    sni_entry = struct.pack("!BH", 0x00, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    # Handshake body:
    # client_version (2), random (32), session_id (1 len + 0), ciphers (2 len + 2), comp (1 len + 1), extensions
    client_version = b"\x03\x03"
    random_bytes = b"\x00" * 32
    session_id = b"\x00"
    ciphers = struct.pack("!H", 2) + b"\xc0\x2f"
    compression = b"\x01\x00"

    handshake_body = client_version + random_bytes + session_id + ciphers + compression + extensions
    # Handshake header: type 0x01 (1 byte), length (3 bytes)
    handshake_header = struct.pack("!B", 0x01) + len(handshake_body).to_bytes(3, byteorder="big")
    handshake = handshake_header + handshake_body

    # TLS Record header: content_type 0x16 (1 byte), version 0x0301 (2 bytes), length (2 bytes)
    record_header = struct.pack("!BHH", 0x16, 0x0301, len(handshake))
    return record_header + handshake


def test_sni_extraction_success():
    packet = build_synthetic_client_hello("bank.example.com")
    sni = extract_sni_from_client_hello(packet)
    assert sni == "bank.example.com"


def test_sni_extraction_non_tls():
    garbage = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"
    assert extract_sni_from_client_hello(garbage) is None


def test_sni_extraction_truncated():
    packet = build_synthetic_client_hello("test.org")[:20]
    assert extract_sni_from_client_hello(packet) is None


def test_sni_extraction_empty():
    assert extract_sni_from_client_hello(b"") is None
