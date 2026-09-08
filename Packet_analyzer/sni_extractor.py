import struct
from typing import Optional


TLS_CONTENT_TYPE_HANDSHAKE = 0x16
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
TLS_HANDSHAKE_TYPE_SERVER_HELLO = 0x02

TLS_VERSION_1_0 = 0x0301
TLS_VERSION_1_1 = 0x0302
TLS_VERSION_1_2 = 0x0303
TLS_VERSION_1_3 = 0x0304

TLS_VERSION_NAMES = {
    TLS_VERSION_1_0: 'TLS 1.0',
    TLS_VERSION_1_1: 'TLS 1.1',
    TLS_VERSION_1_2: 'TLS 1.2',
    TLS_VERSION_1_3: 'TLS 1.3',
}

EXTENSION_TYPE_SNI = 0x0000
EXTENSION_TYPE_ALPN = 0x0010
EXTENSION_TYPE_SUPPORTED_GROUPS = 0x000A
EXTENSION_TYPE_KEY_SHARE = 0x0033
EXTENSION_TYPE_SUPPORTED_VERSIONS = 0x002B


class SNIExtractor:
    """Extract Server Name Indication (SNI) from TLS Client Hello messages.

    The SNI is sent in PLAINTEXT as part of the TLS handshake, before
    encryption begins. This is how DPI engines identify HTTPS traffic
    by destination domain even when the traffic is encrypted.

    TLS Record Layer (5 bytes):
    ┌──────────┬──────────┬──────────┐
    │ Type(1)  │ Ver(2)   │ Len(2)   │
    └──────────┴──────────┴──────────┘

    Handshake (4+ bytes):
    ┌──────────┬──────────┬──────────────┐
    │ Type(1)  │ Len(3)   │ Body(...)    │
    │ 0x01     │          │ ClientHello  │
    └──────────┴──────────┴──────────────┘

    Client Hello body:
    ┌──────────┬──────────┬────────────────┐
    │ Ver(2)   │ Random   │ Session ID     │
    │          │ (32)     │ (1+var)        │
    ├──────────┼──────────┼────────────────┤
    │ Cipher   │ Compress │ Extensions     │
    │ Suites   │ ion(1+)  │ (2+var)        │
    │ (2+var)  │          │                │
    └──────────┴──────────┴────────────────┘

    SNI Extension (type 0x0000):
    ┌──────────┬──────────┬──────────┬──────────┐
    │ Type(2)  │ Len(2)   │ ListLen  │ Entry:   │
    │ 0x0000   │          │ (2)      │ type(1)  │
    │          │          │          │ len(2)   │
    │          │          │          │ name(var)│
    └──────────┴──────────┴──────────┴──────────┘
    """

    TLS_RECORD_HEADER_LEN = 5  # type(1) + version(2) + length(2)
    TLS_HANDSHAKE_HEADER_LEN = 4  # type(1) + length(3)
    TLS_CLIENT_HELLO_MIN_LEN = 38  # version(2) + random(32) + session_id(1) + ... 

    @staticmethod
    def extract_sni(payload: bytes) -> Optional[str]:
        """Extract SNI hostname from TLS Client Hello payload.

        Returns the domain name (e.g., 'www.youtube.com') or None.
        """
        if len(payload) < SNIExtractor.TLS_RECORD_HEADER_LEN:
            return None

        content_type = payload[0]
        record_version = struct.unpack('!H', payload[1:3])[0]
        record_length = struct.unpack('!H', payload[3:5])[0]

        if content_type != TLS_CONTENT_TYPE_HANDSHAKE:
            return None

        if record_version < TLS_VERSION_1_0 or record_version > TLS_VERSION_1_3:
            return None

        offset = SNIExtractor.TLS_RECORD_HEADER_LEN
        return SNIExtractor._parse_client_hello(payload, offset)

    @staticmethod
    def _parse_client_hello(
        data: bytes, offset: int
    ) -> Optional[str]:
        """Parse a TLS Client Hello handshake message.

        The client hello body layout:
        - Handshake type (1 byte)
        - Handshake length (3 bytes, big-endian)
        - Client version (2 bytes)
        - Random (32 bytes)
        - Session ID length (1 byte)
        - Session ID (variable)
        - Cipher suite length (2 bytes)
        - Cipher suites (variable)
        - Compression length (1 byte)
        - Compression methods (variable)
        - Extensions length (2 bytes)
        - Extensions (variable): TLV format
        """
        if offset + SNIExtractor.TLS_HANDSHAKE_HEADER_LEN > len(data):
            return None

        handshake_type = data[offset]
        handshake_length = (data[offset + 1] << 16) | \
                           (data[offset + 2] << 8) | \
                           data[offset + 3]

        if handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
            return None

        offset += SNIExtractor.TLS_HANDSHAKE_HEADER_LEN

        if offset + SNIExtractor.TLS_CLIENT_HELLO_MIN_LEN > len(data):
            return None

        # Skip version (2 bytes)
        offset += 2

        # Skip random (32 bytes)
        offset += 32

        # Skip session ID
        if offset >= len(data):
            return None
        session_id_length = data[offset]
        offset += 1 + session_id_length

        # Skip cipher suites
        if offset + 2 > len(data):
            return None
        cipher_suites_length = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2 + cipher_suites_length

        # Skip compression methods
        if offset >= len(data):
            return None
        compression_length = data[offset]
        offset += 1 + compression_length

        # Parse extensions
        if offset + 2 > len(data):
            return None
        extensions_length = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2

        extensions_end = offset + extensions_length
        if extensions_end > len(data):
            extensions_end = len(data)

        return SNIExtractor._find_sni_extension(data, offset, extensions_end)

    @staticmethod
    def _find_sni_extension(
        data: bytes, offset: int, end: int
    ) -> Optional[str]:
        """Walk through TLS extensions to find the SNI extension (type 0x0000).

        Each extension:
        - Type (2 bytes)
        - Length (2 bytes)
        - Data (variable)

        SNI extension data:
        - Server name list length (2 bytes)
        - Server name entry:
          - Name type (1 byte): 0x00 = host_name
          - Name length (2 bytes)
          - Name (variable, UTF-8 string)
        """
        while offset + 4 <= end:
            ext_type = struct.unpack('!H', data[offset:offset + 2])[0]
            ext_length = struct.unpack('!H', data[offset + 2:offset + 4])[0]
            ext_data_offset = offset + 4
            ext_data_end = ext_data_offset + ext_length

            if ext_type == EXTENSION_TYPE_SNI:
                # Parse SNI extension
                if ext_data_offset + 2 > ext_data_end:
                    return None

                sni_list_length = struct.unpack(
                    '!H', data[ext_data_offset:ext_data_offset + 2]
                )[0]
                sni_offset = ext_data_offset + 2

                if sni_offset + 3 > ext_data_end:
                    return None

                name_type = data[sni_offset]
                name_length = struct.unpack(
                    '!H', data[sni_offset + 1:sni_offset + 3]
                )[0]

                if name_type != 0x00:
                    return None

                name_offset = sni_offset + 3
                if name_offset + name_length > ext_data_end:
                    return None

                hostname = data[name_offset:name_offset + name_length]
                try:
                    return hostname.decode('utf-8')
                except UnicodeDecodeError:
                    return None

            offset = ext_data_end

        return None

    @staticmethod
    def extract_tls_version(payload: bytes) -> Optional[str]:
        """Extract TLS version from the record layer."""
        if len(payload) < 3:
            return None
        record_version = struct.unpack('!H', payload[1:3])[0]
        return TLS_VERSION_NAMES.get(record_version)

    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        """Quick check if this payload is a TLS Client Hello."""
        if len(payload) < 6:
            return False
        return (
            payload[0] == TLS_CONTENT_TYPE_HANDSHAKE and
            payload[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        )


class HTTPHostExtractor:
    """Extract the Host header from unencrypted HTTP requests.

    For HTTP (port 80), the domain is in the Host header:
        GET /path HTTP/1.1\r\n
        Host: www.example.com\r\n
        ...
    """

    @staticmethod
    def extract_host(payload: bytes) -> Optional[str]:
        try:
            text = payload.decode('utf-8', errors='ignore')
        except Exception:
            return None

        for line in text.split('\r\n'):
            if line.lower().startswith('host:'):
                host = line[5:].strip()
                if host:
                    return host
        return None

    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        try:
            text = payload.decode('utf-8', errors='ignore')
            return any(
                text.startswith(method)
                for method in ('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')
            )
        except Exception:
            return False


class DNSExtractor:
    """Extract domain names from DNS query packets.

    DNS query format:
    ┌──────────┬──────────┬──────────┬──────────┐
    │ ID (2)   │ Flags(2) │ QCount(2)│ ...      │
    └──────────┴──────────┴──────────┴──────────┘

    Each query:
    ┌────────────────────┬──────────┬──────────┐
    │ Name (var)         │ Type(2)  │ Class(2) │
    │ label|len|label... │          │          │
    └────────────────────┴──────────┴──────────┘

    Name encoding: sequence of [length_byte][label_bytes]...
    Terminated by a zero-length label (0x00).
    Example: 3www6google3com0 → www.google.com
    """

    DNS_HEADER_LEN = 12

    @staticmethod
    def extract_queries(payload: bytes) -> list[str]:
        if len(payload) < DNSExtractor.DNS_HEADER_LEN:
            return []

        questions = struct.unpack('!H', payload[4:6])[0]

        offset = DNSExtractor.DNS_HEADER_LEN
        domains = []

        for _ in range(questions):
            if offset >= len(payload):
                break
            domain, offset = DNSExtractor._parse_dns_name(payload, offset)
            if domain:
                domains.append(domain)
            offset += 4  # skip type (2) + class (2)

        return domains

    @staticmethod
    def _parse_dns_name(data: bytes, offset: int) -> tuple[Optional[str], int]:
        """Parse a DNS name in label format.

        DNS names are sequences of length-prefixed labels:
        [3]www[6]google[3]com[0] → www.google.com

        Handles DNS name compression (pointer to earlier name):
        If top 2 bits of length byte are set (0xC0), the remaining
        14 bits are an offset to the actual name in the packet.
        """
        labels = []
        original_offset = offset
        jumped = False

        while True:
            if offset >= len(data):
                return None, original_offset

            length = data[offset]

            # Check for DNS compression pointer (0xC0 = 11xxxxxx)
            if length & 0xC0:
                if offset + 2 > len(data):
                    return None, original_offset
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                offset = pointer
                continue

            offset += 1

            if length == 0:
                break

            if offset + length > len(data):
                return None, original_offset

            labels.append(data[offset:offset + length].decode('utf-8', errors='ignore'))
            offset += length

        if not jumped:
            return '.'.join(labels), offset
        else:
            return '.'.join(labels), original_offset
