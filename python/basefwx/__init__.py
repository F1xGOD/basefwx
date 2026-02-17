from .main import *

def b64encode(string: str): return basefwx.b64encode(string)
def b512encode(string: str, code: str="", use_master: bool = True): return basefwx.b512encode(string, code, use_master=use_master)
def b256encode(string: str): return basefwx.b256encode(string)
def n10encode(data): return basefwx.n10encode(data)
def n10encode_bytes(data): return basefwx.n10encode_bytes(data)
def b1024encode(string: str): return basefwx.b1024encode(string)
def bi512encode(string: str): return basefwx.bi512encode(string)
def pb512encode(string: str, code: str="", use_master: bool = True): return basefwx.pb512encode(string, code, use_master=use_master)
def a512encode(string: str): return basefwx.a512encode(string)
def hash512(string: str): return basefwx.hash512(string)
def uhash513(string: str): return basefwx.uhash513(string)

def b64decode(string: str): return basefwx.b64decode(string)
def b256decode(string: str): return basefwx.b256decode(string)
def n10decode(string: str, errors: str = "strict"): return basefwx.n10decode(string, errors=errors)
def n10decode_bytes(string: str): return basefwx.n10decode_bytes(string)
def a512decode(string: str): return basefwx.a512decode(string)
def b512decode(string: str, code: str="", use_master: bool = True): return basefwx.b512decode(string, code, use_master=use_master)
def pb512decode(string: str, code: str="", use_master: bool = True): return basefwx.pb512decode(string, code, use_master=use_master)

def jMGe(
    path: str,
    password: str = "",
    output: str | None = None,
    *,
    keep_meta: bool = False,
    keep_input: bool = False
):
    return basefwx.MediaCipher.encrypt_media(
        path,
        password,
        output=output,
        keep_meta=keep_meta,
        keep_input=keep_input
    )

def jMGd(path: str, password: str = "", output: str | None = None):
    return basefwx.MediaCipher.decrypt_media(path, password, output=output)

def b512encodefile(file: str, code: str, strip_metadata: bool = False, use_master: bool = True): return basefwx.b512file_encode(file, code, strip_metadata=strip_metadata, use_master=use_master)
def b512decodefile(file: str, code: str="", strip_metadata: bool = False, use_master: bool = True): return basefwx.b512file_decode(file, code, strip_metadata=strip_metadata, use_master=use_master)
def b512handlefile(file: str, code: str="", strip_metadata: bool = False, use_master: bool = True, silent: bool = False): return basefwx.b512file(file, code, strip_metadata=strip_metadata, use_master=use_master, silent=silent)
def fwxAES(
    file: str,
    code: str = "",
    light: bool = True,
    strip_metadata: bool = False,
    use_master: bool = True,
    silent: bool = False,
    *,
    output: str | None = None,
    normalize: bool = False,
    normalize_threshold: int | None = None,
    cover_phrase: str = "low taper fade",
    legacy: bool = False,
    ignore_media: bool = False,
    keep_meta: bool = False,
    keep_input: bool = False
):
    if legacy:
        return basefwx.AESfile(
            file,
            code,
            light,
            strip_metadata=strip_metadata,
            use_master=use_master,
            silent=silent,
            keep_input=keep_input
    )
    return basefwx.fwxAES_file(
        file,
        code,
        output=output,
        use_master=use_master,
        normalize=normalize,
        normalize_threshold=normalize_threshold,
        cover_phrase=cover_phrase,
        ignore_media=ignore_media,
        keep_meta=keep_meta,
        keep_input=keep_input
    )

def fwxAES_encrypt_raw(plaintext: bytes, password: str | bytes, use_master: bool = True):
    return basefwx.fwxAES_encrypt_raw(plaintext, password, use_master=use_master)
def fwxAES_decrypt_raw(blob: bytes, password: str | bytes, use_master: bool = True):
    return basefwx.fwxAES_decrypt_raw(blob, password, use_master=use_master)
def fwxAES_encrypt_stream(source, dest, password: str | bytes, use_master: bool = True, chunk_size: int | None = None):
    return basefwx.fwxAES_encrypt_stream(source, dest, password, use_master=use_master, chunk_size=chunk_size)
def fwxAES_decrypt_stream(source, dest, password: str | bytes, use_master: bool = True, chunk_size: int | None = None):
    return basefwx.fwxAES_decrypt_stream(source, dest, password, use_master=use_master, chunk_size=chunk_size)
def normalize_wrap(blob: bytes, cover_phrase: str = "low taper fade"): return basefwx.normalize_wrap(blob, cover_phrase)
def normalize_unwrap(text: str): return basefwx.normalize_unwrap(text)
def b512file_encode_bytes(data: bytes, ext: str, code: str, strip_metadata: bool = False, use_master: bool = True, enable_aead: bool | None = None):
    return basefwx.b512file_encode_bytes(data, ext, code, strip_metadata=strip_metadata, use_master=use_master, enable_aead=enable_aead)
def b512file_decode_bytes(blob: bytes, code: str, strip_metadata: bool = False, use_master: bool = True):
    return basefwx.b512file_decode_bytes(blob, code, strip_metadata=strip_metadata, use_master=use_master)
def pb512file_encode_bytes(data: bytes, ext: str, code: str, strip_metadata: bool = False, use_master: bool = True):
    return basefwx.pb512file_encode_bytes(data, ext, code, strip_metadata=strip_metadata, use_master=use_master)
def pb512file_decode_bytes(blob: bytes, code: str, strip_metadata: bool = False, use_master: bool = True):
    return basefwx.pb512file_decode_bytes(blob, code, strip_metadata=strip_metadata, use_master=use_master)
