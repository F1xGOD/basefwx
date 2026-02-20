"""File-oriented convenience wrappers."""

from .main import basefwx


def b512encodefile(
    file: str,
    code: str,
    strip_metadata: bool = False,
    use_master: bool = True,
):
    return basefwx.b512file_encode(
        file,
        code,
        strip_metadata=strip_metadata,
        use_master=use_master,
    )


def b512decodefile(
    file: str,
    code: str = "",
    strip_metadata: bool = False,
    use_master: bool = True,
):
    return basefwx.b512file_decode(
        file,
        code,
        strip_metadata=strip_metadata,
        use_master=use_master,
    )


def b512handlefile(
    file: str,
    code: str = "",
    strip_metadata: bool = False,
    use_master: bool = True,
    silent: bool = False,
):
    return basefwx.b512file(
        file,
        code,
        strip_metadata=strip_metadata,
        use_master=use_master,
        silent=silent,
    )


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
    archive_original: bool = True,
    keep_input: bool = False,
):
    if legacy:
        return basefwx.AESfile(
            file,
            code,
            light,
            strip_metadata=strip_metadata,
            use_master=use_master,
            silent=silent,
            keep_input=keep_input,
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
        archive_original=archive_original,
        keep_input=keep_input,
    )


def fwxAES_encrypt_raw(plaintext: bytes, password: str | bytes, use_master: bool = True):
    return basefwx.fwxAES_encrypt_raw(plaintext, password, use_master=use_master)


def fwxAES_decrypt_raw(blob: bytes, password: str | bytes, use_master: bool = True):
    return basefwx.fwxAES_decrypt_raw(blob, password, use_master=use_master)


def fwxAES_encrypt_stream(
    source,
    dest,
    password: str | bytes,
    use_master: bool = True,
    chunk_size: int | None = None,
):
    return basefwx.fwxAES_encrypt_stream(
        source,
        dest,
        password,
        use_master=use_master,
        chunk_size=chunk_size,
    )


def fwxAES_decrypt_stream(
    source,
    dest,
    password: str | bytes,
    use_master: bool = True,
    chunk_size: int | None = None,
):
    return basefwx.fwxAES_decrypt_stream(
        source,
        dest,
        password,
        use_master=use_master,
        chunk_size=chunk_size,
    )


LiveEncryptor = basefwx.LiveEncryptor
LiveDecryptor = basefwx.LiveDecryptor


def fwxAES_live_encrypt_chunks(
    chunks,
    password: str | bytes,
    use_master: bool = True,
):
    return basefwx.fwxAES_live_encrypt_chunks(
        chunks,
        password,
        use_master=use_master,
    )


def fwxAES_live_decrypt_chunks(
    chunks,
    password: str | bytes,
    use_master: bool = True,
):
    return basefwx.fwxAES_live_decrypt_chunks(
        chunks,
        password,
        use_master=use_master,
    )


def fwxAES_live_encrypt_stream(
    source,
    dest,
    password: str | bytes,
    use_master: bool = True,
    chunk_size: int | None = None,
):
    return basefwx.fwxAES_live_encrypt_stream(
        source,
        dest,
        password,
        use_master=use_master,
        chunk_size=chunk_size,
    )


def fwxAES_live_decrypt_stream(
    source,
    dest,
    password: str | bytes,
    use_master: bool = True,
    chunk_size: int | None = None,
):
    return basefwx.fwxAES_live_decrypt_stream(
        source,
        dest,
        password,
        use_master=use_master,
        chunk_size=chunk_size,
    )


def normalize_wrap(blob: bytes, cover_phrase: str = "low taper fade"):
    return basefwx.normalize_wrap(blob, cover_phrase)


def normalize_unwrap(text: str):
    return basefwx.normalize_unwrap(text)


def b512file_encode_bytes(
    data: bytes,
    ext: str,
    code: str,
    strip_metadata: bool = False,
    use_master: bool = True,
    enable_aead: bool | None = None,
):
    return basefwx.b512file_encode_bytes(
        data,
        ext,
        code,
        strip_metadata=strip_metadata,
        use_master=use_master,
        enable_aead=enable_aead,
    )


def b512file_decode_bytes(
    blob: bytes,
    code: str,
    strip_metadata: bool = False,
    use_master: bool = True,
):
    return basefwx.b512file_decode_bytes(
        blob,
        code,
        strip_metadata=strip_metadata,
        use_master=use_master,
    )


def pb512file_encode_bytes(
    data: bytes,
    ext: str,
    code: str,
    strip_metadata: bool = False,
    use_master: bool = True,
):
    return basefwx.pb512file_encode_bytes(
        data,
        ext,
        code,
        strip_metadata=strip_metadata,
        use_master=use_master,
    )


def pb512file_decode_bytes(
    blob: bytes,
    code: str,
    strip_metadata: bool = False,
    use_master: bool = True,
):
    return basefwx.pb512file_decode_bytes(
        blob,
        code,
        strip_metadata=strip_metadata,
        use_master=use_master,
    )


__all__ = [
    "b512decodefile",
    "b512encodefile",
    "b512file_decode_bytes",
    "b512file_encode_bytes",
    "b512handlefile",
    "fwxAES",
    "fwxAES_decrypt_raw",
    "fwxAES_decrypt_stream",
    "fwxAES_encrypt_raw",
    "fwxAES_encrypt_stream",
    "fwxAES_live_decrypt_chunks",
    "fwxAES_live_decrypt_stream",
    "fwxAES_live_encrypt_chunks",
    "fwxAES_live_encrypt_stream",
    "LiveDecryptor",
    "LiveEncryptor",
    "normalize_unwrap",
    "normalize_wrap",
    "pb512file_decode_bytes",
    "pb512file_encode_bytes",
]
