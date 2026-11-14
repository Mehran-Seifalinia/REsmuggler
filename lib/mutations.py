"""Payload mutation profiles for Transfer-Encoding / Content-Length tests."""

from typing import Callable, Dict


def default_mutations() -> Dict[str, str]:
    mutations: Dict[str, str] = {}
    mutations["nameprefix1"] = " Transfer-Encoding: chunked"
    mutations["tabprefix1"] = "Transfer-Encoding:\tchunked"
    mutations["tabprefix2"] = "Transfer-Encoding\t:\tchunked"
    mutations["space1"] = "Transfer-Encoding : chunked"
    mutations["cl_duplicate"] = "Content-Length: 5\r\nContent-Length: 6"
    mutations["cl_underscore"] = "Content_Length: 5"
    mutations["cl_space_suffix"] = "Content-Length : 5"
    mutations["te_plus_cl"] = "Transfer-Encoding: chunked\r\nContent-Length: 5"
    mutations["cl_plus_te"] = "Content-Length: 5\r\nTransfer-Encoding: chunked"

    edge_codepoints = [0x1, 0x4, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0x1F, 0x20, 0x7F, 0xA0, 0xFF]
    for codepoint in edge_codepoints:
        char = chr(codepoint)
        tag = f"{codepoint:02x}"
        mutations[f"midspace-{tag}"] = f"Transfer-Encoding:{char}chunked"
        mutations[f"postspace-{tag}"] = f"Transfer-Encoding{char}: chunked"
        mutations[f"prespace-{tag}"] = f"{char}Transfer-Encoding: chunked"
        mutations[f"endspace-{tag}"] = f"Transfer-Encoding: chunked{char}"
    return mutations


def exhaustive_mutations() -> Dict[str, str]:
    mutations: Dict[str, str] = {}
    mutations.update(default_mutations())

    mutations["nameprefix1"] = " Transfer-Encoding: chunked"
    mutations["tabprefix1"] = "Transfer-Encoding:\tchunked"
    mutations["tabprefix2"] = "Transfer-Encoding\t:\tchunked"
    mutations["spacejoin1"] = "Transfer Encoding: chunked"
    mutations["underjoin1"] = "Transfer_Encoding: chunked"
    mutations["smashed"] = "Transfer Encoding:chunked"
    mutations["space1"] = "Transfer-Encoding : chunked"
    mutations["valueprefix1"] = "Transfer-Encoding:  chunked"
    mutations["vertprefix1"] = "Transfer-Encoding:\u000Bchunked"
    mutations["commaCow"] = "Transfer-Encoding: chunked, cow"
    mutations["cowComma"] = "Transfer-Encoding: cow, chunked"
    mutations["contentEnc"] = "Content-Encoding: chunked"
    mutations["linewrapped1"] = "Transfer-Encoding:\n chunked"
    mutations["quoted"] = 'Transfer-Encoding: "chunked"'
    mutations["aposed"] = "Transfer-Encoding: 'chunked'"
    mutations["lazygrep"] = "Transfer-Encoding: chunk"
    mutations["sarcasm"] = "TrAnSFer-EnCODinG: cHuNkeD"
    mutations["yelling"] = "TRANSFER-ENCODING: CHUNKED"
    mutations["0dsuffix"] = "Transfer-Encoding: chunked\r"
    mutations["tabsuffix"] = "Transfer-Encoding: chunked\t"
    mutations["revdualchunk"] = "Transfer-Encoding: cow\r\nTransfer-Encoding: chunked"
    mutations["0dspam"] = "Transfer\r-Encoding: chunked"
    mutations["nested"] = "Transfer-Encoding: cow chunked bar"
    mutations["spaceFF"] = "Transfer-Encoding:\xFFchunked"
    mutations["accentCH"] = "Transfer-Encoding: ch\x96nked"
    mutations["accentTE"] = "Transf\x82r-Encoding: chunked"
    mutations["x-rout"] = "X:X\rTransfer-Encoding: chunked"
    mutations["x-nout"] = "X:X\nTransfer-Encoding: chunked"

    for codepoint in range(0x1, 0x20):
        char = chr(codepoint)
        tag = f"{codepoint:02x}"
        mutations[f"midspace-{tag}"] = f"Transfer-Encoding:{char}chunked"
        mutations[f"postspace-{tag}"] = f"Transfer-Encoding{char}: chunked"
        mutations[f"prespace-{tag}"] = f"{char}Transfer-Encoding: chunked"
        mutations[f"endspace-{tag}"] = f"Transfer-Encoding: chunked{char}"

    for codepoint in range(0x7F, 0x100):
        char = chr(codepoint)
        tag = f"{codepoint:02x}"
        mutations[f"midspace-{tag}"] = f"Transfer-Encoding:{char}chunked"
        mutations[f"postspace-{tag}"] = f"Transfer-Encoding{char}: chunked"
        mutations[f"prespace-{tag}"] = f"{char}Transfer-Encoding: chunked"
        mutations[f"endspace-{tag}"] = f"Transfer-Encoding: chunked{char}"
    return mutations


def doubles_mutations() -> Dict[str, str]:
    mutations: Dict[str, str] = {}
    codepoints = list(range(0x1, 0x21)) + list(range(0x7F, 0x100))
    for codepoint in codepoints:
        char = chr(codepoint)
        tag = f"{codepoint:02x}"
        mutations[f"{tag}-{tag}-XX-XX"] = f"{char}Transfer-Encoding{char}: chunked"
        mutations[f"{tag}-XX-{tag}-XX"] = f"{char}Transfer-Encoding:{char}chunked"
        mutations[f"{tag}-XX-XX-{tag}"] = f"{char}Transfer-Encoding: chunked{char}"
        mutations[f"XX-{tag}-{tag}-XX"] = f"Transfer-Encoding{char}:{char}chunked"
        mutations[f"XX-{tag}-XX-{tag}"] = f"Transfer-Encoding{char}: chunked{char}"
        mutations[f"XX-XX-{tag}-{tag}"] = f"Transfer-Encoding:{char}chunked{char}"
    return mutations


def cl0_mutations() -> Dict[str, str]:
    mutations: Dict[str, str] = {}
    mutations["cl0_basic"] = "Content-Length: 0"
    mutations["cl0_expect"] = "Content-Length: 0\r\nExpect: 100-continue"
    mutations["cl0_obf_expect_1"] = "Content-Length: 0\r\nExpect: y 100-continue"
    mutations["cl0_obf_expect_2"] = "Content-Length: 0\r\nExpect:  100-continue "
    mutations["cl0_obf_expect_3"] = "Content-Length: 0\r\nExpect: 100-continue\t"
    return mutations


def h2_mutations() -> Dict[str, str]:
    mutations: Dict[str, str] = {}
    mutations["h2_cl"] = "content-length: 6"
    mutations["h2_te"] = "transfer-encoding: chunked"
    mutations["h2_crlf_te"] = "foo: bar\r\nTransfer-Encoding: chunked"
    mutations["h2_crlf_cl"] = "foo: bar\r\nContent-Length: 6"
    return mutations


MUTATION_PROFILES: Dict[str, Callable[[], Dict[str, str]]] = {
    "default": default_mutations,
    "exhaustive": exhaustive_mutations,
    "doubles": doubles_mutations,
    "cl0": cl0_mutations,
    "h2": h2_mutations,
}