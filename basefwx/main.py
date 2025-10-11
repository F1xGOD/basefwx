# BASEFWX ENCRYPTION ENGINE ->

class basefwx:
    import base64
    import sys
    import secrets
    import pathlib
    import random
    import typing
    import json
    from PIL import Image
    from io import BytesIO
    import numpy as np
    import os
    import zlib
    import hashlib
    import string
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.backends import default_backend
    from datetime import datetime, timezone

    MAX_INPUT_BYTES = 15 * 1024 * 1024  # 15 MiB ceiling for source files
    PROGRESS_BAR_WIDTH = 30
    FWX_DELIM = "A8igTOmG"
    FWX_HEAVY_DELIM = "673827837628292873"
    META_DELIM = "::FWX-META::"
    ENGINE_VERSION = "3.0.0"

    class _ProgressReporter:
        """Lightweight textual progress reporter with two WinRAR-style bars."""

        def __init__(self, total_files: int, stream=None):
            self.total_files = max(total_files, 1)
            self.stream = stream or basefwx.sys.stdout

        @staticmethod
        def _render_bar(fraction: float, width: int = PROGRESS_BAR_WIDTH) -> str:
            fraction = max(0.0, min(1.0, fraction))
            filled = int(round(fraction * width))
            filled = min(filled, width)
            bar = '#' * filled + '.' * (width - filled)
            return f"[{bar}] {fraction * 100:6.2f}%"

        def update(self, file_index: int, fraction: float, phase: str, path: "basefwx.pathlib.Path") -> None:
            overall_fraction = (file_index + max(0.0, min(1.0, fraction))) / self.total_files
            overall = self._render_bar(overall_fraction)
            current = self._render_bar(fraction)
            label = path.name if path else ""
            self.stream.write(
                f"Overall {overall} ({file_index}/{self.total_files} files complete)\n"
            )
            self.stream.write(
                f"File    {current} phase: {phase}{' [' + label + ']' if label else ''}\n"
            )
            self.stream.flush()

        def finalize_file(self, file_index: int, path: "basefwx.pathlib.Path") -> None:
            overall_fraction = (file_index + 1) / self.total_files
            overall = self._render_bar(overall_fraction)
            self.stream.write(
                f"Overall {overall} ({file_index + 1}/{self.total_files} files complete)\n"
            )
            label = path.name if path else ""
            current = self._render_bar(1.0)
            self.stream.write(
                f"File    {current} phase: done{' [' + label + ']' if label else ''}\n"
            )
            self.stream.flush()

    @staticmethod
    def _human_readable_size(num_bytes: int) -> str:
        units = ["B", "KiB", "MiB", "GiB"]
        value = float(num_bytes)
        for unit in units:
            if value < 1024.0 or unit == units[-1]:
                return f"{value:.2f} {unit}"
            value /= 1024.0
        return f"{value:.2f} TiB"

    @staticmethod
    def _build_metadata(method: str, strip: bool, use_master: bool) -> str:
        if strip:
            return ""
        timestamp = basefwx.datetime.now(basefwx.timezone.utc).isoformat().replace("+00:00", "Z")
        version = getattr(basefwx, "__version__", basefwx.ENGINE_VERSION)
        info = {
            "ENC-TIME": timestamp,
            "ENC-VERSION": version,
            "ENC-METHOD": method,
            "ENC-MASTER": "yes" if use_master else "no"
        }
        data = basefwx.json.dumps(info, separators=(',', ':')).encode('utf-8')
        return basefwx.base64.b64encode(data).decode('utf-8')

    @staticmethod
    def _decode_metadata(blob: str) -> "basefwx.typing.Dict[str, basefwx.typing.Any]":
        if not blob:
            return {}
        try:
            raw = basefwx.base64.b64decode(blob.encode('utf-8'))
            return basefwx.json.loads(raw.decode('utf-8'))
        except Exception:
            return {}

    @staticmethod
    def _split_metadata(payload: str) -> "basefwx.typing.Tuple[str, str]":
        if basefwx.META_DELIM in payload:
            return payload.split(basefwx.META_DELIM, 1)
        return "", payload

    @staticmethod
    def _apply_strip_attributes(path: "basefwx.pathlib.Path") -> None:
        try:
            basefwx.os.utime(path, (0, 0))
        except Exception:
            pass

    @staticmethod
    def _normalize_path(path_like: "basefwx.typing.Union[str, basefwx.pathlib.Path]") -> "basefwx.pathlib.Path":
        if isinstance(path_like, basefwx.pathlib.Path):
            path = path_like
        else:
            path = basefwx.pathlib.Path(str(path_like))
        path = path.expanduser()
        try:
            return path.resolve(strict=False)
        except Exception:
            return path

    @staticmethod
    def _ensure_existing_file(path: "basefwx.pathlib.Path") -> None:
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Input file not found: {path}")

    @staticmethod
    def _ensure_size_limit(path: "basefwx.pathlib.Path", max_bytes: int = None) -> None:
        limit = max_bytes or basefwx.MAX_INPUT_BYTES
        size = path.stat().st_size
        if size > limit:
            human_size = basefwx._human_readable_size(size)
            human_limit = basefwx._human_readable_size(limit)
            raise ValueError(
                f"{path.name} is {human_size}, exceeding the {human_limit} limit for this mode"
            )

    @staticmethod
    def _resolve_password(password: str, use_master: bool = True) -> str:
        if password == "":
            if not use_master:
                raise ValueError("Password required when master key usage is disabled")
            master_home = basefwx.os.path.expanduser("~/master.pem")
            if basefwx.os.path.exists(master_home):
                password = master_home
            elif basefwx.os.path.exists("W:\\master.pem"):
                password = "W:\\master.pem"
            else:
                raise ValueError("Failed to locate master.pem for default password")

        if basefwx.os.path.isfile(password):
            with open(password, "r", encoding="utf-8") as handle:
                password = handle.read()
        return password

    @staticmethod
    def _coerce_file_list(files) -> "basefwx.typing.List[basefwx.pathlib.Path]":
        if isinstance(files, (str, basefwx.pathlib.Path)):
            candidates = [files]
        else:
            candidates = list(files)
        if not candidates:
            raise ValueError("No files provided")
        normalized = []
        for item in candidates:
            normalized.append(basefwx._normalize_path(item))
        return normalized

    def __init__(self):
        self.sys.set_int_max_str_digits(2000000000)
        pass

    @staticmethod
    def generate_random_string(length):
        """Generates a random string of the specified length."""

        alphabet = basefwx.string.ascii_letters + basefwx.string.digits
        return ''.join(basefwx.secrets.choice(alphabet) for i in range(length))

    @staticmethod
    def derive_key_from_text(text, salt, key_length_bytes=32):

        """Derives an AES key from text using PBKDF2."""

        # Use PBKDF2 to derive a key from the text and salt
        key = basefwx.hashlib.pbkdf2_hmac(
            "sha256",
            text.encode(),
            salt.encode(),
            100000,  # Number of iterations (higher is more secure)
            dklen=key_length_bytes
        )
        return key

    @staticmethod
    def _derive_user_key(password: str) -> bytes:

        salt = (password[:5] + "*&fdhauiGGVGUDoiai").encode("utf-8")
        kdf = basefwx.PBKDF2HMAC(
            algorithm=basefwx.hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=basefwx.default_backend()
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def encryptAES(plaintext: str, user_key: str, use_master: bool = True) -> bytes:
        if user_key == "":
            if use_master:
                if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                    user_key = basefwx.os.path.expanduser("~/master.pem")
                elif basefwx.os.path.exists("W:\\master.pem"):
                    user_key = "W:\\master.pem"
                else:
                    print("Failed To Encode File, The Key File Is Corrupted!")
                    basefwx.sys.exit(1)
            else:
                raise ValueError("Password required when master key usage is disabled")
        basefwx.sys.set_int_max_str_digits(2000000000)
        ephemeral_key = basefwx.os.urandom(32)
        user_derived_key = basefwx._derive_user_key(user_key)
        ephemeral_key_b64 = basefwx.base64.b64encode(ephemeral_key).decode('utf-8')
        iv_user = basefwx.os.urandom(16)
        cipher_user = basefwx.Cipher(basefwx.algorithms.AES(user_derived_key), basefwx.modes.CBC(iv_user))
        encryptor_user = cipher_user.encryptor()
        padder = basefwx.padding.PKCS7(128).padder()
        padded_ephemeral_key = padder.update(ephemeral_key_b64.encode('utf-8')) + padder.finalize()
        ephemeral_enc_user = encryptor_user.update(padded_ephemeral_key) + encryptor_user.finalize()
        ephemeral_enc_user = iv_user + ephemeral_enc_user
        if use_master:
            keypem = basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk))
            master_public_key = basefwx.serialization.load_pem_public_key(
                keypem,
                backend=basefwx.default_backend()
            )
            ephemeral_enc_master = master_public_key.encrypt(
                ephemeral_key,
                basefwx.asym_padding.OAEP(
                    mgf=basefwx.asym_padding.MGF1(algorithm=basefwx.hashes.SHA256()),
                    algorithm=basefwx.hashes.SHA256(),
                    label=None
                )
            )
        else:
            ephemeral_enc_master = b""
        iv_data = basefwx.os.urandom(16)
        cipher_data = basefwx.Cipher(basefwx.algorithms.AES(ephemeral_key), basefwx.modes.CBC(iv_data))
        encryptor_data = cipher_data.encryptor()
        padder2 = basefwx.padding.PKCS7(128).padder()
        padded_plaintext = padder2.update(plaintext.encode('utf-8')) + padder2.finalize()
        ciphertext = encryptor_data.update(padded_plaintext) + encryptor_data.finalize()
        ciphertext = iv_data + ciphertext

        def int_to_4(i):
            return i.to_bytes(4, byteorder='big', signed=False)

        blob = b''
        blob += int_to_4(len(ephemeral_enc_user)) + ephemeral_enc_user
        blob += int_to_4(len(ephemeral_enc_master)) + ephemeral_enc_master
        blob += int_to_4(len(ciphertext)) + ciphertext
        return blob

    @staticmethod
    def decryptAES(encrypted_blob: bytes, key: str = "", use_master: bool = True) -> str:
        basefwx.sys.set_int_max_str_digits(2000000000)
        if key == "":
            if use_master:
                if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                    key = basefwx.os.path.expanduser("~/master.pem")
                elif basefwx.os.path.exists("W:\\master.pem"):
                    key = "W:\\master.pem"
                else:
                    print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                    basefwx.sys.exit(1)
            else:
                raise ValueError("Password required when master key usage is disabled")

        def read_chunk(in_bytes, offset):
            length = int.from_bytes(in_bytes[offset:offset + 4], 'big')
            offset += 4
            chunk = in_bytes[offset:offset + length]
            offset += length
            return chunk, offset

        offset = 0
        ephemeral_enc_user, offset = read_chunk(encrypted_blob, offset)
        ephemeral_enc_master, offset = read_chunk(encrypted_blob, offset)
        ciphertext, offset = read_chunk(encrypted_blob, offset)
        master_blob_present = len(ephemeral_enc_master) > 0
        if not use_master and master_blob_present:
            raise ValueError("Master key required to decrypt this payload")

        if use_master and master_blob_present:
            if basefwx.os.path.isfile(key):
                with open(key, "rb") as f:
                    private_key_data = f.read()
                private_key = basefwx.serialization.load_pem_private_key(
                    private_key_data,
                    password=None,
                    backend=basefwx.default_backend()
                )
            elif "BEGIN PRIVATE KEY" in key or "BEGIN RSA PRIVATE KEY" in key:
                private_key = basefwx.serialization.load_pem_private_key(
                    key.encode('utf-8'),
                    password=None,
                    backend=basefwx.default_backend()
                )
            else:
                raise ValueError("Master private key required for this payload")
            ephemeral_key = private_key.decrypt(
                ephemeral_enc_master,
                basefwx.asym_padding.OAEP(
                    mgf=basefwx.asym_padding.MGF1(algorithm=basefwx.hashes.SHA256()),
                    algorithm=basefwx.hashes.SHA256(),
                    label=None
                )
            )
        else:
            user_derived_key = basefwx._derive_user_key(key)
            iv_user = ephemeral_enc_user[:16]
            enc_user_key = ephemeral_enc_user[16:]
            cipher_user = basefwx.Cipher(basefwx.algorithms.AES(user_derived_key), basefwx.modes.CBC(iv_user))
            decryptor_user = cipher_user.decryptor()
            padded_b64 = decryptor_user.update(enc_user_key) + decryptor_user.finalize()
            unpadder = basefwx.padding.PKCS7(128).unpadder()
            ephemeral_key_b64 = unpadder.update(padded_b64) + unpadder.finalize()
            ephemeral_key = basefwx.base64.b64decode(ephemeral_key_b64)
        iv_data = ciphertext[:16]
        real_ciphertext = ciphertext[16:]
        cipher_data = basefwx.Cipher(basefwx.algorithms.AES(ephemeral_key), basefwx.modes.CBC(iv_data))
        decryptor_data = cipher_data.decryptor()
        padded_plaintext = decryptor_data.update(real_ciphertext) + decryptor_data.finalize()
        unpadder2 = basefwx.padding.PKCS7(128).unpadder()
        plaintext = unpadder2.update(padded_plaintext) + unpadder2.finalize()
        return plaintext.decode('utf-8')

    # noinspection SpellCheckingInspection
    MASTERk = b'eJxdkkuPqkAUhPf3V7gnhqcCy25otEGbh4DIThpEXgMKCvLrZ+auLrdWJ1XJl5NUrdc/gmiHycoJ4AFrKwtdfr31n9U/OmIMcQkIzKvHvSp26shB4CIDAFsDrgJ+cy23fm4EtmMsqcqs7pFEKIu3XpMMC1g/2s2Zc3tyqfVDnAs3NhKTV/uR6qir77GgtW+nHXiYevAmPv1TwvLzMPM1tXRnfBnuAlZqVuTMjlyAsH0q1Hf84GNlVK25Zy5XGTNyU0GM7phwmnI1OTO2aRoKuCDpFCAwXhcw2aM5XwWkSx5Jt0NeCfYiAXfTG3JKQ2meh8yIxIzJ8pY5l/E2SGuHZG4hMh9L9oXlZw/cSxWkCPThJzoBeJRiGrKWhns/cp6tMqiCpLtmIyuI9yZjK79T6r8AKg/8JJyBuYClQokiZrOZNtFQGMY12diwsTw3uZ2b4fbep0Z8CDTVE62w+9qzEivOJ/PLO0n40l1kx17AdiPWgQvgwvxbOiL6/zv4BsbIl0s='

    # REVERSIBLE  - SECURITY: ❙
    @staticmethod
    def b64encode(string: str):

        return basefwx.base64.b64encode(string.encode('utf-8')).decode('utf-8')

    @staticmethod
    def b64decode(string: str):

        return basefwx.base64.b64decode(string.encode('utf-8')).decode('utf-8')

    @staticmethod
    def hash512(string: str):

        return basefwx.hashlib.sha256(string.encode('utf-8')).hexdigest()

    @staticmethod
    def uhash513(string: str):

        sti = string
        return basefwx.hashlib.sha256(basefwx.b512encode(basefwx.hashlib.sha512(
            basefwx.hashlib.sha1(
                basefwx.hashlib.sha256(sti.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest().encode(
                "utf-8")).hexdigest(), basefwx.hashlib.sha512(sti.encode('utf-8')).hexdigest()).encode(
            'utf-8')).hexdigest()

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙
    @staticmethod
    def pb512encode(t, p, use_master: bool = True):
        if p == "":
            if use_master:
                if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                    p = open(basefwx.os.path.expanduser("~/master.pem")).read()
                elif basefwx.os.path.exists("W:\\master.pem"):
                    p = open("W:\\master.pem").read()
                else:
                    print("Failed To Encode File, The Key File Is Corrupted!")
                    basefwx.sys.exit(1)
            else:
                raise ValueError("Password required when master key usage is disabled")

        def mdcode(s):
            r = ""
            for b in bytearray(s.encode('ascii')):
                x = str(int(bin(b)[2:], 2))
                r += str(len(x)) + x
            return r

        def encrypt_chunks_to_string(m, n):
            c = len(n)
            k = int(n)
            x = 10 ** c
            l = len(m)
            pp = ((l + c - 1) // c) * c
            mm = m.ljust(pp, '0')
            z = []
            for i in range(0, pp, c):
                d = int(mm[i:i + c])
                e = (d + k) % x
                z.append(str(e).zfill(c))
            return ''.join(z) + str(l).zfill(10)

        def mcode(s):
            r = ""
            h = 0
            L = 0
            o = 0
            arr = list(s)
            for x in arr:
                h += 1
                if x != "":
                    if h == 1:
                        L = int(x)
                        r += chr(int(s[h:h + L]))
                        o = h
                    elif L + o + 1 == h:
                        L = int(x)
                        r += chr(int(s[h:h + L]))
                        o = h
            return r

        def pb512encode_chunk(txt, code):
            return encrypt_chunks_to_string(mdcode(txt), mdcode(code)).replace("-", "0").replace("=", "4G5tRA")

        def _derive_user_key(u):
            s = (u[:5] + "*&fdhauiGGVGUDoiai").encode("utf-8")
            k = basefwx.PBKDF2HMAC(algorithm=basefwx.hashes.SHA256(), length=32, salt=s, iterations=100000,
                                   backend=basefwx.default_backend())
            return k.derive(u.encode("utf-8"))

        c = ''.join(basefwx.random.choices(basefwx.string.digits, k=16))
        enc = pb512encode_chunk(t, c)
        cb = enc.encode('utf-8')
        ck = basefwx.base64.b64encode(c.encode('utf-8')).decode('utf-8')
        uk = _derive_user_key(p)
        iv1 = basefwx.os.urandom(16)
        cu = basefwx.Cipher(basefwx.algorithms.AES(uk), basefwx.modes.CBC(iv1)).encryptor()
        pad = basefwx.padding.PKCS7(128).padder()
        p1 = pad.update(ck.encode('utf-8')) + pad.finalize()
        ecu = cu.update(p1) + cu.finalize()
        ecu = iv1 + ecu
        if use_master:
            keypem = basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk))
            pk = basefwx.serialization.load_pem_public_key(keypem, backend=basefwx.default_backend())
            ecm = pk.encrypt(c.encode('utf-8'),
                             basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),
                                                       algorithm=basefwx.hashes.SHA256(), label=None))
        else:
            ecm = b""

        def i4(x):
            return x.to_bytes(4, "big")

        blob = i4(len(ecu)) + ecu + i4(len(ecm)) + ecm + i4(len(cb)) + cb
        ln = len(blob)
        val = int.from_bytes(blob, 'big')
        return str(ln).zfill(6) + str(val)

    @staticmethod
    def pb512decode(digs, key, use_master: bool = True):
        if key == "":
            if use_master:
                if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                    key = open(basefwx.os.path.expanduser("~/master.pem")).read()
                elif basefwx.os.path.exists("W:\\master.pem"):
                    key = open("W:\\master.pem").read()
                else:
                    print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                    basefwx.sys.exit(1)
            else:
                raise ValueError("Password required when master key usage is disabled")
        k = key

        def mdcode(s):
            r = ""
            for b in bytearray(s.encode('ascii')):
                x = str(int(bin(b)[2:], 2))
                r += str(len(x)) + x
            return r

        def decrypt_chunks_from_string(e, n):
            c = len(n)
            z = []
            kx = int(n)
            x = 10 ** c
            l = int(e[-10:])
            e2 = e[:-10]
            for i in range(0, len(e2), c):
                d = int(e2[i:i + c])
                f = (d - kx) % x
                z.append(str(f).zfill(c))
            return ''.join(z)[:l]

        def mcode(s):
            r = ""
            h = 0
            L = 0
            o = 0
            arr = list(s)
            for x in arr:
                h += 1
                if x != "":
                    if h == 1:
                        L = int(x)
                        r += chr(int(s[h:h + L]))
                        o = h
                    elif L + o + 1 == h:
                        L = int(x)
                        r += chr(int(s[h:h + L]))
                        o = h
            return r

        def pb512decode_chunk(txt, code):
            rr = txt
            if rr and rr[0] == "0":
                rr = "-" + rr[1:]
            return mcode(decrypt_chunks_from_string(rr, mdcode(code)))

        def _derive_user_key(u):
            s = (u[:5] + "*&fdhauiGGVGUDoiai").encode("utf-8")
            k = basefwx.PBKDF2HMAC(algorithm=basefwx.hashes.SHA256(), length=32, salt=s, iterations=100000,
                                   backend=basefwx.default_backend())
            return k.derive(u.encode("utf-8"))

        ln = int(digs[:6])
        val = int(digs[6:])
        raw = val.to_bytes((val.bit_length() + 7) // 8, 'big')
        if len(raw) < ln:
            raw = (b"\x00" * (ln - len(raw))) + raw

        def rc(b, o):
            l = int.from_bytes(b[o:o + 4], 'big')
            o += 4
            c = b[o:o + l]
            o += l
            return c, o

        o = 0
        ecu, o = rc(raw, o)
        ecm, o = rc(raw, o)
        cb, o = rc(raw, o)
        master_blob_present = len(ecm) > 0
        if not use_master and master_blob_present:
            raise ValueError("Master key required to decode this payload")

        if use_master and master_blob_present:
            if "BEGIN PRIVATE KEY" in k or "BEGIN RSA PRIVATE KEY" in k:
                pk = basefwx.serialization.load_pem_private_key(k.encode('utf-8'), None, backend=basefwx.default_backend())
            elif basefwx.os.path.isfile(k):
                with open(k, 'rb') as fh:
                    pem = fh.read()
                pk = basefwx.serialization.load_pem_private_key(pem, None, backend=basefwx.default_backend())
            else:
                raise ValueError("Master private key required for this payload")
            cc = pk.decrypt(ecm, basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),
                                                           algorithm=basefwx.hashes.SHA256(), label=None))
        else:
            uk = _derive_user_key(k)
            iv = ecu[:16]
            cf = ecu[16:]
            d = basefwx.Cipher(basefwx.algorithms.AES(uk), basefwx.modes.CBC(iv)).decryptor()
            p = d.update(cf) + d.finalize()
            up = basefwx.padding.PKCS7(128).unpadder()
            cc = basefwx.base64.b64decode(up.update(p) + up.finalize())
        return pb512decode_chunk(cb.decode('utf-8'), cc.decode('utf-8'))

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙

    @staticmethod
    def b512encode(string, user_key, use_master: bool = True):
        if user_key == "":
            if use_master:
                if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                    user_key = open(basefwx.os.path.expanduser("~/master.pem")).read()
                elif basefwx.os.path.exists("W:\\master.pem"):
                    user_key = open("W:\\master.pem").read()
                else:
                    print("Failed To Encode File, The Key File Is Corrupted!")
                    basefwx.sys.exit(1)
            else:
                raise ValueError("Password required when master key usage is disabled")

        def mdcode(s):
            r = ""
            for b in bytearray(s.encode('ascii')):
                x = str(int(bin(b)[2:], 2))
                r += str(len(x)) + x
            return r

        def encrypt_chunks_to_string(bn, ky):
            cs = len(ky)
            kn = int(ky)
            mv = 10 ** cs
            ol = len(bn)
            pl = ((ol + cs - 1) // cs) * cs
            pad = bn.ljust(pl, '0')
            out = []
            for i in range(0, pl, cs):
                ck = int(pad[i:i + cs])
                ev = (ck + kn) % mv
                out.append(str(ev).zfill(cs))
            return ''.join(out) + str(ol).zfill(10)

        def mainenc(s, c):
            return basefwx.fwx256bin(
                encrypt_chunks_to_string(mdcode(s), mdcode(c)).replace("-", "0")
            ).replace("=", "4G5tRA")

        def _derive_user_key(usr):
            st = (usr[:5] + "*&fdhauiGGVGUDoiai").encode("utf-8")
            kd = basefwx.PBKDF2HMAC(
                algorithm=basefwx.hashes.SHA256(),
                length=32,
                salt=st,
                iterations=100000,
                backend=basefwx.default_backend()
            )
            return kd.derive(usr.encode("utf-8"))

        ep = ''.join(basefwx.random.choices(basefwx.string.digits, k=16))
        ec = mainenc(string, ep)
        ec_bin = ec.encode('utf-8')
        ep_b64 = basefwx.base64.b64encode(ep.encode('utf-8'))

        derived = _derive_user_key(user_key)
        iv = basefwx.os.urandom(16)
        ciph = basefwx.Cipher(basefwx.algorithms.AES(derived), basefwx.modes.CBC(iv)).encryptor()
        pad = basefwx.padding.PKCS7(128).padder()
        padded = pad.update(ep_b64) + pad.finalize()
        epu = ciph.update(padded) + ciph.finalize()
        epu = iv + epu

        if use_master:
            keypem = basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk))

            pk = basefwx.serialization.load_pem_public_key(keypem, backend=basefwx.default_backend())
            epm = pk.encrypt(
                ep.encode('utf-8'),
                basefwx.asym_padding.OAEP(
                    mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),
                    algorithm=basefwx.hashes.SHA256(),
                    label=None
                )
            )
        else:
            epm = b""

        def i4(x):
            return x.to_bytes(4, 'big')

        blob = i4(len(epu)) + epu + i4(len(epm)) + epm + i4(len(ec_bin)) + ec_bin

        # Instead of decimal string => base64-encode the final bytes => return as a normal string
        return basefwx.base64.b64encode(blob).decode('utf-8')

    @staticmethod
    def b512decode(enc, key="", use_master: bool = True):
        if key == "":
            if use_master:
                if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                    key = open(basefwx.os.path.expanduser("~/master.pem")).read()
                elif basefwx.os.path.exists("W:\\master.pem"):
                    key = open("W:\\master.pem").read()
                else:
                    print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                    basefwx.sys.exit(1)
            else:
                raise ValueError("Password required when master key usage is disabled")

        def mdcode(s):
            r = ""
            for b in bytearray(s.encode('ascii')):
                x = str(int(bin(b)[2:], 2))
                r += str(len(x)) + x
            return r

        def decrypt_chunks_from_string(e, n):
            c = len(n)
            kx = int(n)
            x = 10 ** c
            l = int(e[-10:])
            e2 = e[:-10]
            z = []
            for i in range(0, len(e2), c):
                d = int(e2[i:i + c])
                f = (d - kx) % x
                z.append(str(f).zfill(c))
            return ''.join(z)[:l]

        def mcode(s):
            r = ""
            h = 0
            L = 0
            o = 0
            arr = list(s)
            for xx in arr:
                h += 1
                if xx != "":
                    if h == 1:
                        L = int(xx)
                        r += chr(int(s[h:h + L]))
                        o = h
                    elif L + o + 1 == h:
                        L = int(xx)
                        r += chr(int(s[h:h + L]))
                        o = h
            return r

        def b512decode_chunk(txt, c):
            st = txt.replace("4G5tRA", "=")
            x = basefwx.fwx256unbin(st)
            if x and x[0] == "0": x = "-" + x[1:]
            return mcode(decrypt_chunks_from_string(x, mdcode(c)))

        def _derive_user_key(u):
            s = (u[:5] + "*&fdhauiGGVGUDoiai").encode("utf-8")
            kd = basefwx.PBKDF2HMAC(
                algorithm=basefwx.hashes.SHA256(),
                length=32,
                salt=s,
                iterations=100000,
                backend=basefwx.default_backend()
            )
            return kd.derive(u.encode("utf-8"))

        raw = basefwx.base64.b64decode(enc)  # decode from base64 string

        def rc(b, o):
            l = int.from_bytes(b[o:o + 4], 'big')
            o += 4
            cc = b[o:o + l]
            o += l
            return cc, o

        o = 0
        epu, o = rc(raw, o)
        epm, o = rc(raw, o)
        ec, o = rc(raw, o)

        master_blob_present = len(epm) > 0
        if not use_master and master_blob_present:
            raise ValueError("Master key required to decode this payload")

        if use_master and master_blob_present:
            if "BEGIN PRIVATE KEY" in key or "BEGIN RSA PRIVATE KEY" in key:
                pk = basefwx.serialization.load_pem_private_key(
                    key.encode('utf-8'),
                    None,
                    backend=basefwx.default_backend()
                )
            elif basefwx.os.path.isfile(key):
                with open(key, 'rb') as fh:
                    pem = fh.read()
                pk = basefwx.serialization.load_pem_private_key(
                    pem,
                    None,
                    backend=basefwx.default_backend()
                )
            else:
                raise ValueError("Master private key required for this payload")
            ep = pk.decrypt(
                epm,
                basefwx.asym_padding.OAEP(
                    mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),
                    algorithm=basefwx.hashes.SHA256(),
                    label=None
                )
            )
        else:
            uk = _derive_user_key(key)
            iv = epu[:16]
            cf = epu[16:]
            dec = basefwx.Cipher(basefwx.algorithms.AES(uk), basefwx.modes.CBC(iv)).decryptor()
            out = dec.update(cf) + dec.finalize()
            up = basefwx.padding.PKCS7(128).unpadder()
            ep = basefwx.base64.b64decode(up.update(out) + up.finalize())

        return b512decode_chunk(ec.decode('utf-8'), ep.decode('utf-8'))

    @staticmethod
    def _b512_encode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            total_files: int = 1,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)

        use_master_effective = use_master and not strip_metadata
        data = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "base64", path)

        b64_payload = basefwx.base64.b64encode(data).decode('utf-8')
        ext_token = basefwx.b512encode(path.suffix or "", password, use_master=use_master_effective)
        data_token = basefwx.b512encode(b64_payload, password, use_master=use_master_effective)
        if reporter:
            reporter.update(file_index, 0.65, "b256", path)

        metadata_blob = basefwx._build_metadata("FWX512R", strip_metadata, use_master_effective)
        body = f"{ext_token}{basefwx.FWX_DELIM}{data_token}"
        payload = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body
        payload_bytes = payload.encode('utf-8')
        approx_size = len(payload_bytes)

        output_path = path.with_suffix('.fwx')
        with open(output_path, 'wb') as handle:
            handle.write(payload_bytes)

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
        basefwx.os.chmod(output_path, 0)
        basefwx.os.remove(path)

        if reporter:
            reporter.update(
                file_index,
                0.9,
                f"write (~{basefwx._human_readable_size(approx_size)})",
                output_path
            )
            reporter.finalize_file(file_index, output_path)

        return output_path, approx_size

    @staticmethod
    def _b512_decode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            total_files: int = 1,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        if reporter:
            reporter.update(file_index, 0.1, "read", path)

        with open(path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        metadata_blob, content_core = basefwx._split_metadata(content)
        meta = basefwx._decode_metadata(metadata_blob)
        master_hint = meta.get("ENC-MASTER") if meta else None
        use_master_effective = use_master and not strip_metadata
        if master_hint == "no":
            use_master_effective = False

        try:
            header, payload = content_core.split(basefwx.FWX_DELIM, 1)
        except ValueError as exc:
            raise ValueError("Malformed FWX container") from exc

        if reporter:
            reporter.update(file_index, 0.35, "b256", path)

        ext = basefwx.b512decode(header, password, use_master=use_master_effective)
        data_b64 = basefwx.b512decode(payload, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.65, "base64", path)

        raw_bytes = basefwx.base64.b64decode(data_b64)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(raw_bytes)

        basefwx.os.remove(path)

        if strip_metadata:
            basefwx._apply_strip_attributes(target)
        if reporter:
            reporter.update(file_index, 0.9, "write", target)
            reporter.finalize_file(file_index, target)

        return target, len(raw_bytes)

    @staticmethod
    def b512file_encode(file: str, code: str, strip_metadata: bool = False, use_master: bool = True):
        try:
            effective_use_master = use_master and not strip_metadata
            password = basefwx._resolve_password(code, use_master=effective_use_master)
            path = basefwx._normalize_path(file)
            basefwx._b512_encode_path(path, password, strip_metadata=strip_metadata, use_master=effective_use_master)
            return "SUCCESS!"
        except Exception as exc:
            print(f"Failed to encode {file}: {exc}")
            return "FAIL!"

    @staticmethod
    def b512file(files: "basefwx.typing.Union[str, basefwx.pathlib.Path, basefwx.typing.Iterable[basefwx.typing.Union[str, basefwx.pathlib.Path]]]", password: str, strip_metadata: bool = False, use_master: bool = True):
        paths = basefwx._coerce_file_list(files)
        effective_use_master = use_master and not strip_metadata
        try:
            resolved_password = basefwx._resolve_password(password, use_master=effective_use_master)
        except Exception as exc:
            print(f"Password resolution failed: {exc}")
            return "FAIL!" if len(paths) == 1 else {str(p): "FAIL!" for p in paths}

        reporter = basefwx._ProgressReporter(len(paths))
        results = {}

        for idx, path in enumerate(paths):
            try:
                basefwx._ensure_existing_file(path)
            except FileNotFoundError:
                reporter.update(idx, 0.0, "missing", path)
                reporter.finalize_file(idx, path)
                results[str(path)] = "FAIL!"
                continue

            try:
                if path.suffix.lower() == ".fwx":
                    basefwx._b512_decode_path(path, resolved_password, reporter, idx, len(paths), strip_metadata, effective_use_master)
                else:
                    basefwx._b512_encode_path(path, resolved_password, reporter, idx, len(paths), strip_metadata, effective_use_master)
                results[str(path)] = "SUCCESS!"
            except Exception as exc:
                reporter.update(idx, 0.0, f"error: {exc}", path)
                reporter.finalize_file(idx, path)
                results[str(path)] = "FAIL!"

        if len(paths) == 1:
            return next(iter(results.values()))
        return results

    class sepImageCipher:
        _MARKER = b'--ENCRYPTED_PWD--'

        @staticmethod
        def _load_master_pubkey():
            pem = basefwx.zlib.decompress(
                basefwx.base64.b64decode(basefwx.MASTERk)
            )
            return basefwx.serialization.load_pem_public_key(pem)

        @staticmethod
        def _load_master_privkey():
            for p in (
                    basefwx.os.path.expanduser('~/master.pem'),
                    r'W:\master.pem'
            ):
                if basefwx.os.path.exists(p):
                    data = open(p, 'rb').read()
                    return basefwx.serialization.load_pem_private_key(data, password=None)
            raise FileNotFoundError('No master.pem found')

        @staticmethod
        def scramble_indices(size: int, key: bytes):
            seed = int(basefwx.hashlib.sha256(key).hexdigest(), 16) % 2 ** 32
            basefwx.np.random.seed(seed)
            idx = basefwx.np.arange(size)
            basefwx.np.random.shuffle(idx)
            return idx

        @staticmethod
        def rotate8(x: int, k: int) -> int:
            return ((x << k) & 0xFF) | (x >> (8 - k))

        @staticmethod
        def encrypt_image_inv(path: str, password: str, output: str = 'chaos_inv.png'):
            key_bytes = password.encode()
            img = basefwx.Image.open(path).convert('RGB')
            arr = basefwx.np.array(img)
            h, w, _ = arr.shape
            flat = arr.reshape(-1, 3)

            # pixel shuffle & transform
            scrambled = flat[
                basefwx.ImageCipher.scramble_indices(flat.shape[0], key_bytes)
            ].copy()
            digest = basefwx.hashlib.sha256(key_bytes).digest()
            offsets = basefwx.np.frombuffer(
                digest * ((flat.shape[0] // len(digest)) + 1),
                dtype=basefwx.np.uint8
            )[:flat.shape[0]]
            perms = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
            for i in range(flat.shape[0]):
                off = int(offsets[i])
                r, g, b = map(int, scrambled[i])
                # shift
                r = (r + off) & 0xFF
                g = (g + off // 2) & 0xFF
                b = (b + off // 3) & 0xFF
                # swap
                p = perms[off % 6]
                r, g, b = ([r, g, b][j] for j in p)
                # rotate
                k = (off % 7) + 1
                scrambled[i] = [
                    basefwx.ImageCipher.rotate8(r, k),
                    basefwx.ImageCipher.rotate8(g, k),
                    basefwx.ImageCipher.rotate8(b, k)
                ]

            img_enc = basefwx.Image.fromarray(scrambled.reshape(h, w, 3))
            img_enc.save(output)

            # RSA-encrypt password and append to file
            pub = basefwx.ImageCipher._load_master_pubkey()
            enc_pwd = pub.encrypt(
                key_bytes,
                basefwx.asym_padding.OAEP(
                    mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),
                    algorithm=basefwx.hashes.SHA256(),
                    label=None
                )
            )
            data = open(output, 'rb').read()
            with open(output, 'wb') as f:
                f.write(data)
                f.write(basefwx.ImageCipher._MARKER)
                f.write(len(enc_pwd).to_bytes(4, 'big'))
                f.write(enc_pwd)
            print(f'🔥 Encrypted image+pwd → {output}')

        @staticmethod
        def decrypt_image_inv(path: str, password: str = '', output: str = 'decrypted_inv.png'):
            data = open(path, 'rb').read()
            idx = data.rfind(basefwx.ImageCipher._MARKER)
            if idx < 0:
                raise ValueError('No embedded password marker')
            png_data = data[:idx]
            rest = data[idx + len(basefwx.ImageCipher._MARKER):]
            size = int.from_bytes(rest[:4], 'big')
            enc_pwd = rest[4:4 + size]

            # recover password bytes
            if password:
                key_bytes = password.encode()
            else:
                priv = basefwx.ImageCipher._load_master_privkey()
                key_bytes = priv.decrypt(
                    enc_pwd,
                    basefwx.asym_padding.OAEP(
                        mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),
                        algorithm=basefwx.hashes.SHA256(),
                        label=None
                    )
                )
                print('🔓 Password recovered via master key')

            # decrypt image
            img = basefwx.Image.open(basefwx.BytesIO(png_data)).convert('RGB')
            arr = basefwx.np.array(img)
            h, w, _ = arr.shape
            flat = arr.reshape(-1, 3)
            digest = basefwx.hashlib.sha256(key_bytes).digest()
            offsets = basefwx.np.frombuffer(
                digest * ((flat.shape[0] // len(digest)) + 1),
                dtype=basefwx.np.uint8
            )[:flat.shape[0]]
            perms = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
            temp = flat.copy()
            # invert rotate
            for i in range(flat.shape[0]):
                k = (int(offsets[i]) % 7) + 1
                r, g, b = temp[i]
                flat[i] = [
                    ((r >> k) | (r << (8 - k))) & 0xFF,
                    ((g >> k) | (g << (8 - k))) & 0xFF,
                    ((b >> k) | (b << (8 - k))) & 0xFF
                ]
            # invert swap
            temp = flat.copy()
            for i in range(flat.shape[0]):
                off = int(offsets[i]);
                p = perms[off % 6]
                inv = [p.index(j) for j in range(3)];
                vals = temp[i]
                flat[i] = [vals[inv[j]] for j in range(3)]
            # invert shift & unshuffle
            recovered = basefwx.np.zeros_like(flat)
            idx_map = basefwx.ImageCipher.scramble_indices(flat.shape[0], key_bytes)
            out_arr = basefwx.np.zeros_like(flat)
            for i in range(flat.shape[0]):
                off = int(offsets[i]);
                r, g, b = flat[i]
                recovered[i] = [
                    (r - off) & 0xFF,
                    (g - off // 2) & 0xFF,
                    (b - off // 3) & 0xFF
                ]
            for i, orig in enumerate(idx_map):
                out_arr[orig] = recovered[i]

            basefwx.Image.fromarray(out_arr.reshape(h, w, 3)).save(output)
            print(f'✅ Decrypted → {output}')

    class ImageCipher:
        _MARKER = b'--ENCRYPTED_PWD--'

        @staticmethod
        def _load_master_pubkey():
            pem = basefwx.zlib.decompress(
                basefwx.base64.b64decode(basefwx.MASTERk)
            )
            return basefwx.serialization.load_pem_public_key(pem)

        @staticmethod
        def _load_master_privkey():
            for p in (
                    basefwx.os.path.expanduser('~/master.pem'),
                    r'W:\master.pem'
            ):
                if basefwx.os.path.exists(p):
                    data = open(p, 'rb').read()
                    return basefwx.serialization.load_pem_private_key(data, password=None)
            raise FileNotFoundError('No master.pem found')

        @staticmethod
        def scramble_indices(size: int, key: bytes):
            seed = int(basefwx.hashlib.sha256(key).hexdigest(), 16) % 2 ** 32
            basefwx.np.random.seed(seed)
            idx = basefwx.np.arange(size)
            basefwx.np.random.shuffle(idx)
            return idx

        @staticmethod
        def rotate8(x: int, k: int) -> int:
            return ((x << k) & 0xFF) | (x >> (8 - k))

        @staticmethod
        def encrypt_image_inv(path: str, password: str, output: str = 'chaos_inv.png'):
            key_bytes = password.encode()
            img = basefwx.Image.open(path).convert('RGB')
            arr = basefwx.np.array(img)
            h, w, _ = arr.shape
            flat = arr.reshape(-1, 3)

            # pixel shuffle & transform
            scrambled = flat[
                basefwx.ImageCipher.scramble_indices(flat.shape[0], key_bytes)
            ].copy()
            digest = basefwx.hashlib.sha256(key_bytes).digest()
            offsets = basefwx.np.frombuffer(
                digest * ((flat.shape[0] // len(digest)) + 1),
                dtype=basefwx.np.uint8
            )[:flat.shape[0]]
            perms = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
            for i in range(flat.shape[0]):
                off = int(offsets[i])
                r, g, b = map(int, scrambled[i])
                # shift
                r = (r + off) & 0xFF
                g = (g + off // 2) & 0xFF
                b = (b + off // 3) & 0xFF
                # swap
                p = perms[off % 6]
                r, g, b = ([r, g, b][j] for j in p)
                # rotate
                k = (off % 7) + 1
                scrambled[i] = [
                    basefwx.ImageCipher.rotate8(r, k),
                    basefwx.ImageCipher.rotate8(g, k),
                    basefwx.ImageCipher.rotate8(b, k)
                ]

            img_enc = basefwx.Image.fromarray(scrambled.reshape(h, w, 3))
            img_enc.save(output)

            # RSA-encrypt password and append to file
            pub = basefwx.ImageCipher._load_master_pubkey()
            enc_pwd = pub.encrypt(
                key_bytes,
                basefwx.asym_padding.OAEP(
                    mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),
                    algorithm=basefwx.hashes.SHA256(),
                    label=None
                )
            )
            data = open(output, 'rb').read()
            with open(output, 'wb') as f:
                f.write(data)
                f.write(basefwx.ImageCipher._MARKER)
                f.write(len(enc_pwd).to_bytes(4, 'big'))
                f.write(enc_pwd)
            print(f'🔥 Encrypted image+pwd → {output}')

        @staticmethod
        def decrypt_image_inv(path: str, password: str = '', output: str = 'decrypted_inv.png'):
            data = open(path, 'rb').read()
            idx = data.rfind(basefwx.ImageCipher._MARKER)
            if idx < 0:
                raise ValueError('No embedded password marker')
            png_data = data[:idx]
            rest = data[idx + len(basefwx.ImageCipher._MARKER):]
            size = int.from_bytes(rest[:4], 'big')
            enc_pwd = rest[4:4 + size]

            # recover password bytes
            if password:
                key_bytes = password.encode()
            else:
                priv = basefwx.ImageCipher._load_master_privkey()
                key_bytes = priv.decrypt(
                    enc_pwd,
                    basefwx.asym_padding.OAEP(
                        mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),
                        algorithm=basefwx.hashes.SHA256(),
                        label=None
                    )
                )
                print('🔓 Password recovered via master key')

            # decrypt image
            img = basefwx.Image.open(basefwx.BytesIO(png_data)).convert('RGB')
            arr = basefwx.np.array(img)
            h, w, _ = arr.shape
            flat = arr.reshape(-1, 3)
            digest = basefwx.hashlib.sha256(key_bytes).digest()
            offsets = basefwx.np.frombuffer(
                digest * ((flat.shape[0] // len(digest)) + 1),
                dtype=basefwx.np.uint8
            )[:flat.shape[0]]
            perms = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
            temp = flat.copy()
            # invert rotate
            for i in range(flat.shape[0]):
                k = (int(offsets[i]) % 7) + 1
                r, g, b = temp[i]
                flat[i] = [
                    ((r >> k) | (r << (8 - k))) & 0xFF,
                    ((g >> k) | (g << (8 - k))) & 0xFF,
                    ((b >> k) | (b << (8 - k))) & 0xFF
                ]
            # invert swap
            temp = flat.copy()
            for i in range(flat.shape[0]):
                off = int(offsets[i]);
                p = perms[off % 6]
                inv = [p.index(j) for j in range(3)];
                vals = temp[i]
                flat[i] = [vals[inv[j]] for j in range(3)]
            # invert shift & unshuffle
            recovered = basefwx.np.zeros_like(flat)
            idx_map = basefwx.ImageCipher.scramble_indices(flat.shape[0], key_bytes)
            out_arr = basefwx.np.zeros_like(flat)
            for i in range(flat.shape[0]):
                off = int(offsets[i]);
                r, g, b = flat[i]
                recovered[i] = [
                    (r - off) & 0xFF,
                    (g - off // 2) & 0xFF,
                    (b - off // 3) & 0xFF
                ]
            for i, orig in enumerate(idx_map):
                out_arr[orig] = recovered[i]

            basefwx.Image.fromarray(out_arr.reshape(h, w, 3)).save(output)
            print(f'✅ Decrypted → {output}')

    def _aes_light_encode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)

        use_master_effective = use_master and not strip_metadata
        raw = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "base64", path)

        b64_payload = basefwx.base64.b64encode(raw).decode('utf-8')
        metadata_blob = basefwx._build_metadata("AES-LIGHT", strip_metadata, use_master_effective)
        body = (path.suffix or "") + basefwx.FWX_DELIM + b64_payload
        plaintext = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body

        if reporter:
            reporter.update(file_index, 0.55, "AES256", path)

        ciphertext = basefwx.encryptAES(plaintext, password, use_master=use_master_effective)
        compressed = basefwx.zlib.compress(ciphertext)

        if reporter:
            reporter.update(file_index, 0.8, "compress", path)

        output_path = path.with_suffix('.fwx')
        with open(output_path, 'wb') as handle:
            handle.write(compressed)

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
        basefwx.os.chmod(output_path, 0)
        basefwx.os.remove(path)

        if reporter:
            reporter.finalize_file(file_index, output_path)

        return output_path, len(compressed)

    @staticmethod
    def _aes_light_decode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        if reporter:
            reporter.update(file_index, 0.05, "read", path)

        compressed = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "decompress", path)

        try:
            ciphertext = basefwx.zlib.decompress(compressed)
        except basefwx.zlib.error as exc:
            raise ValueError("Compressed FWX payload is corrupted") from exc

        if reporter:
            reporter.update(file_index, 0.55, "AES256", path)

        use_master_effective = use_master and not strip_metadata
        plaintext = basefwx.decryptAES(ciphertext, password, use_master=use_master_effective)
        metadata_blob, payload = basefwx._split_metadata(plaintext)
        _ = basefwx._decode_metadata(metadata_blob)

        try:
            ext, b64_payload = payload.split(basefwx.FWX_DELIM, 1)
        except ValueError as exc:
            raise ValueError("Malformed FWX light payload") from exc

        if reporter:
            reporter.update(file_index, 0.75, "base64", path)

        raw = basefwx.base64.b64decode(b64_payload)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(raw)

        basefwx.os.remove(path)

        if strip_metadata:
            basefwx._apply_strip_attributes(target)
        if reporter:
            reporter.finalize_file(file_index, target)

        return target, len(raw)

    @staticmethod
    def _aes_heavy_encode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx._ensure_size_limit(path)
        if reporter:
            reporter.update(file_index, 0.05, "prepare", path)

        use_master_effective = use_master and not strip_metadata
        raw = path.read_bytes()
        if reporter:
            reporter.update(file_index, 0.25, "base64", path)

        b64_payload = basefwx.base64.b64encode(raw).decode('utf-8')
        ext_token = basefwx.pb512encode(path.suffix or "", password, use_master=use_master_effective)
        data_token = basefwx.pb512encode(b64_payload, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.55, "pb512", path)

        metadata_blob = basefwx._build_metadata("AES-HEAVY", strip_metadata, use_master_effective)
        body = f"{ext_token}{basefwx.FWX_HEAVY_DELIM}{data_token}"
        plaintext = f"{metadata_blob}{basefwx.META_DELIM}{body}" if metadata_blob else body
        ciphertext = basefwx.encryptAES(plaintext, password, use_master=use_master_effective)
        approx_size = len(ciphertext)

        if reporter:
            reporter.update(file_index, 0.8, "AES512", path)

        output_path = path.with_suffix('.fwx')
        with open(output_path, 'wb') as handle:
            handle.write(ciphertext)

        if strip_metadata:
            basefwx._apply_strip_attributes(output_path)
        basefwx.os.chmod(output_path, 0)
        basefwx.os.remove(path)

        human = basefwx._human_readable_size(approx_size)
        print(f"{output_path.name}: approx output size {human}")

        if reporter:
            reporter.update(file_index, 0.95, f"write (~{human})", output_path)
            reporter.finalize_file(file_index, output_path)

        return output_path, approx_size

    @staticmethod
    def _aes_heavy_decode_path(
            path: "basefwx.pathlib.Path",
            password: str,
            reporter: "basefwx._ProgressReporter" = None,
            file_index: int = 0,
            strip_metadata: bool = False,
            use_master: bool = True
    ) -> "basefwx.typing.Tuple[basefwx.pathlib.Path, int]":
        basefwx._ensure_existing_file(path)
        basefwx.os.chmod(path, 0o777)
        if reporter:
            reporter.update(file_index, 0.05, "read", path)

        ciphertext = path.read_bytes()

        if reporter:
            reporter.update(file_index, 0.35, "AES512", path)

        use_master_effective = use_master and not strip_metadata
        plaintext = basefwx.decryptAES(ciphertext, password, use_master=use_master_effective)
        metadata_blob, payload = basefwx._split_metadata(plaintext)
        _ = basefwx._decode_metadata(metadata_blob)

        try:
            ext_token, data_token = payload.split(basefwx.FWX_HEAVY_DELIM, 1)
        except ValueError as exc:
            raise ValueError("Malformed FWX heavy payload") from exc

        if reporter:
            reporter.update(file_index, 0.6, "pb512", path)

        ext = basefwx.pb512decode(ext_token, password, use_master=use_master_effective)
        data_b64 = basefwx.pb512decode(data_token, password, use_master=use_master_effective)

        if reporter:
            reporter.update(file_index, 0.8, "base64", path)

        raw = basefwx.base64.b64decode(data_b64)
        target = path.with_suffix('')
        if ext:
            target = target.with_suffix(ext)

        with open(target, 'wb') as handle:
            handle.write(raw)

        basefwx.os.remove(path)

        if strip_metadata:
            basefwx._apply_strip_attributes(target)
        if reporter:
            reporter.finalize_file(file_index, target)

        return target, len(raw)

    @staticmethod
    def AESfile(
            files: "basefwx.typing.Union[str, basefwx.pathlib.Path, basefwx.typing.Iterable[basefwx.typing.Union[str, basefwx.pathlib.Path]]]",
            password: str = "",
            light: bool = True,
            strip_metadata: bool = False,
            use_master: bool = True
    ):
        basefwx.sys.set_int_max_str_digits(2000000000)
        paths = basefwx._coerce_file_list(files)

        effective_use_master = use_master and not strip_metadata
        try:
            resolved_password = basefwx._resolve_password(password, use_master=effective_use_master)
        except Exception as exc:
            print(f"Password resolution failed: {exc}")
            return "FAIL!" if len(paths) == 1 else {str(p): "FAIL!" for p in paths}

        reporter = basefwx._ProgressReporter(len(paths))
        results = {}

        for idx, path in enumerate(paths):
            try:
                basefwx._ensure_existing_file(path)
            except FileNotFoundError:
                reporter.update(idx, 0.0, "missing", path)
                reporter.finalize_file(idx, path)
                results[str(path)] = "FAIL!"
                continue

            try:
                if path.suffix.lower() == ".fwx":
                    if light:
                        basefwx._aes_light_decode_path(path, resolved_password, reporter, idx, strip_metadata, effective_use_master)
                    else:
                        basefwx._aes_heavy_decode_path(path, resolved_password, reporter, idx, strip_metadata, effective_use_master)
                else:
                    if light:
                        basefwx._aes_light_encode_path(path, resolved_password, reporter, idx, strip_metadata, effective_use_master)
                    else:
                        basefwx._aes_heavy_encode_path(path, resolved_password, reporter, idx, strip_metadata, effective_use_master)
                results[str(path)] = "SUCCESS!"
            except Exception as exc:
                reporter.update(idx, 0.0, f"error: {exc}", path)
                reporter.finalize_file(idx, path)
                results[str(path)] = "FAIL!"

        if len(paths) == 1:
            return next(iter(results.values()))
        return results

    @staticmethod
    def code(string):
        mapping = {
            'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(', 'g': '*&GD2',
            'h': '+*jsGA', 'i': '(aj*a', 'j': 'g%', 'k': '&G{A', 'l': '/IHa', 'm': '*(oa', 'n': '*KA^7',
            'o': ')i*8A', 'p': '*H)PA-G', 'q': '*YFSA', 'r': 'O.-P[A', 's': '{9sl', 't': '*(HARR',
            'u': 'O&iA6u', 'v': 'n):u', 'w': '&^F*GV', 'x': '(*HskW', 'y': '{JM', 'z': 'J.!dA', 'A': '(&Tav',
            'B': 't5', 'C': '*TGA3', 'D': '*GABD', 'E': '{A', 'F': 'pW', 'G': '*UAK(', 'H': '&GH+',
            'I': '&AN)', 'J': 'L&VA', 'K': '(HAF5', 'L': '&F*Va', 'M': '^&FVB', 'N': '(*HSA$i',
            'O': '*IHda&gT', 'P': '&*FAl', 'Q': ')P{A]', 'R': '*Ha$g', 'S': 'G)OA&', 'T': '|QG6',
            'U': 'Qd&^', 'V': 'hA', 'W': '8h^va', 'X': '_9xlA', 'Y': '*J', 'Z': '*;pY&', ' ': 'R7a{',
            '-': '}F', '=': 'OJ)_A', '+': '}J', '&': '%A', '%': 'y{A3s', '#': '.aGa!', '@': 'l@', '!': '/A',
            '^': 'OIp*a', '*': '(U', '(': 'I*Ua]', ')': '{0aD', '{': 'Av[', '}': '9j', '[': '[a)',
            ']': '*&GBA', '|': ']Vc!A', '/': ')*HND_', '~': '(&*GHA', ';': 'K}N=O', ':': 'YGOI&Ah',
            '?': 'Oa', '.': '8y)a', '>': '0{a9', '<': 'v6Yha', ',': 'I8ys#', '0': '(HPA7', '1': '}v',
            '2': '*HAl%', '3': '_)JHS', '4': 'IG(A', '5': '(*GFD', '6': 'IU(&V', '7': '(JH*G', '8': '*GHBA',
            '9': 'U&G*C', '"': 'I(a-s'
        }
        return ''.join(mapping.get(c, c) for c in string)

    @staticmethod
    def fwx256bin(string):
        encoded = basefwx.base64.b32hexencode(basefwx.code(string).encode()).decode()
        padding_count = encoded.count("=")
        return encoded.rstrip("=") + str(padding_count)

    @staticmethod
    def decode(sttr):
        mapping = {
            "I(a-s": "\"", "U&G*C": "9", "*GHBA": "8", "(JH*G": "7", "IU(&V": "6", "(*GFD": "5", "IG(A": "4",
            "_)JHS": "3", "*HAl%": "2", "}v": "1", "(HPA7": "0", "I8ys#": ",", "v6Yha": "<", "0{a9": ">",
            "8y)a": ".", "Oa": "?", "YGOI&Ah": ":", "K}N=O": ";", "(&*GHA": "~", ")*HND_": "/", "]Vc!A": "|",
            "*&GBA": "]", "[a)": "[", "9j": "}", "Av[": "{", "{0aD": ")", "I*Ua]": "(", "(U": "*",
            "OIp*a": "^", "/A": "!", "l@": "@", ".aGa!": "#", "y{A3s": "%", "%A": "&", "}J": "+",
            "OJ)_A": "=", "}F": "-", "R7a{": " ", "*;pY&": "Z", "*J": "Y", "_9xlA": "X", "8h^va": "W",
            "hA": "V", "Qd&^": "U", "|QG6": "T", "G)OA&": "S", "*Ha$g": "R", ")P{A]": "Q", "&*FAl": "P",
            "*IHda&gT": "O", "(*HSA$i": "N", "^&FVB": "M", "&F*Va": "L", "(HAF5": "K", "L&VA": "J",
            "&AN)": "I", "&GH+": "H", "*UAK(": "G", "pW": "F", "{A": "E", "*GABD": "D", "*TGA3": "C",
            "t5": "B", "(&Tav": "A", "J.!dA": "z", "{JM": "y", "(*HskW": "x", "&^F*GV": "w", "n):u": "v",
            "O&iA6u": "u", "*(HARR": "t", "{9sl": "s", "O.-P[A": "r", "*YFSA": "q", "*H)PA-G": "p",
            ")i*8A": "o", "*KA^7": "n", "*(oa": "m", "/IHa": "l", "&G{A": "k", "g%": "j", "(aj*a": "i",
            "+*jsGA": "h", "*&GD2": "g", "(*HGA(": "f", "K5a{": "e", "*YHA": "d", "*&Gs": "c", "&hl": "b",
            "e*1": "a"
        }

        # Get all values sorted by length DESC to avoid collisions (like `*` vs `*UAK(`)
        tokens = sorted(mapping.keys(), key=lambda x: -len(x))

        result = ''
        i = 0
        while i < len(sttr):
            for token in tokens:
                if sttr.startswith(token, i):
                    result += mapping[token]
                    i += len(token)
                    break
            else:
                result += sttr[i]
                i += 1
        return result

    @staticmethod
    def fwx256unbin(string):
        padding_count = int(string[-1])
        base32text = string[:-1] + ("=" * padding_count)
        return basefwx.decode(basefwx.base64.b32hexdecode(base32text.encode('utf-8')).decode('utf-8'))

    @staticmethod
    def b512file_decode(file: str, code: str, strip_metadata: bool = False, use_master: bool = True):
        try:
            effective_use_master = use_master and not strip_metadata
            password = basefwx._resolve_password(code, use_master=effective_use_master)
            path = basefwx._normalize_path(file)
            basefwx._b512_decode_path(path, password, strip_metadata=strip_metadata, use_master=effective_use_master)
            return "SUCCESS!"
        except Exception as exc:
            print(f"Failed to decode {file}: {exc}")
            return "FAIL!"

    @staticmethod
    def bi512encode(string: str):

        code = string[0] + string[len(string) - 1]

        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        def mainenc(string):
            return str(basefwx.hashlib.sha256((basefwx.fwx256bin(
                str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")).encode(
                'utf-8')).hexdigest()).replace("-", "0")

        return mainenc(string)

    # CODELESS ENCODE - SECURITY: ❙
    @staticmethod
    def a512encode(string: str):
        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        code = (str(len(mdcode((string))) * len(mdcode((string)))))

        def mainenc(string):
            return str(len(str(len(mdcode(string))))) + str(len(mdcode(string))) + basefwx.fwx256bin(
                str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")

        return mainenc(string)

    @staticmethod
    def a512decode(string: str):

        def mcode(strin: str):
            end = strin
            eand = list(end)
            finish = ""
            ht = 0
            len = 0
            oht = 0
            for een in eand:
                ht += 1
                if een != "":
                    if ht == 1:
                        len = int(een)
                        finish += str(chr(int(end[ht:len + ht])))
                        oht = ht
                    if ht != 1 and len + oht + 1 == ht:
                        len = int(een)
                        finish += str(chr(int(end[ht:len + ht])))
                        oht = ht
            return finish

        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        def maindc(string):
            result = ""
            try:
                leoa = int(string[0])
                string2 = string[leoa + 1:len(string)]
                cdo = int(string[1:leoa + 1]) * int(string[1:leoa + 1])
                code = (str(cdo))
                string3 = basefwx.fwx256unbin(string2.replace("4G5tRA", "="))
                if string3[0] == "0":
                    string3 = "-" + string3[1:len(string3)]
                result = mcode(str(int(string3) + int(mdcode(code))))
            except:
                result = "AN ERROR OCCURED!"
            return result

        return maindc(string)

    # UNDCODABLE IRREVERSIBLE CODELESS ENCODE - SECURITY: ❙❙❙❙
    @staticmethod
    def b1024encode(string: str):

        def fwx1024uBIN(string: str):
            def fwx512iiBIN(string: str):
                code = string[0] + string[len(string) - 1]

                def mdcode(string: str):
                    st = str(string)
                    binaryvals = map(bin, bytearray(st.encode('ascii')))
                    end = ""
                    for bb in binaryvals:
                        end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
                    return str(end)

                def mainenc(string):
                    return str(basefwx.hashlib.sha256((basefwx.fwx256bin(
                        str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=",
                                                                                                         "4G5tRA")).encode(
                        'utf-8')).hexdigest()).replace("-", "0")

                return mainenc(string)

            def fwx512ciBIN(string: str):
                def mdcode(string: str):
                    st = str(string)
                    binaryvals = map(bin, bytearray(st.encode('ascii')))
                    end = ""
                    for bb in binaryvals:
                        end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
                    return str(end)

                code = (str(len(mdcode((string))) * len(mdcode((string)))))

                def mainenc(string):
                    return str(len(str(len(mdcode(string))))) + str(len(mdcode(string))) + basefwx.fwx256bin(
                        str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")

                return mainenc(string)

            return fwx512iiBIN(fwx512ciBIN(string))

        return fwx1024uBIN(string)

    # CODELESS ENCODE - SECURITY: ❙
    @staticmethod
    def b256decode(string):
        padding_count = int(string[-1])
        base32text = string[:-1] + ("=" * padding_count)
        decoded = basefwx.base64.b32hexdecode(base32text.encode('utf-8')).decode('utf-8')
        return basefwx.decode(decoded)

    @staticmethod
    def b256encode(string):
        raw = basefwx.code(string).encode()
        encoded = basefwx.base64.b32hexencode(raw).decode()
        return encoded.rstrip("=") + str(encoded.count("="))

# ENCRYPTION TYPES:
# BASE64 - b64encode/b64decode  V1.0
# HASH512 - hash512  V1.0
# HASH512U - uhash513 V1.2
# FWX512RP - pb512encode/pb512encode V2.0
# FWX512R - b512encode/b512decode V2.0 ★
# FWX512I - bi512encode V3.4 ★
# FWX512C - a512encode/a512decode V2.0 ❗❗❗ (NOT RECCOMENDED)
# FWX1024I - b1024encode V4.0 ★ (BEST)
# FWX256R - b256encode/b256decode V1.3 ❗❗❗ (NOT RECCOMENDED)

# HOW TO USE: basefwx.ENCRYPTION-TYPE("text","password")


def cli(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="basefwx", description="BASEFWX encryption toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cryptin = subparsers.add_parser(
        "cryptin",
        help="Encrypt/decrypt one or more files using a BASEFWX method"
    )
    cryptin.add_argument(
        "method",
        help="Method name: 512, b512, pb512, aes, aes-light, aes-heavy"
    )
    cryptin.add_argument(
        "paths",
        nargs='+',
        help="One or more file paths"
    )
    cryptin.add_argument(
        "-p", "--password",
        default="",
        help="Password text or PEM path (defaults to master.pem if omitted)"
    )
    cryptin.add_argument(
        "--strip", "--trim",
        dest="strip_metadata",
        action="store_true",
        help="Disable metadata emission and zero timestamps"
    )
    cryptin.add_argument(
        "--no-master",
        dest="use_master",
        action="store_false",
        help="Opt out of master key wrapping/unwrapping"
    )
    cryptin.set_defaults(use_master=True)

    args = parser.parse_args(argv)

    if args.command == "cryptin":
        method = args.method.lower()
        password = args.password or ""
        use_master = args.use_master
        if args.strip_metadata:
            use_master = False
        method_map = {
            "512": "b512",
            "b512": "b512",
            "fwx512": "b512",
            "aes": "aes-light",
            "aes-light": "aes-light",
            "256": "aes-light",
            "light": "aes-light",
            "aes-heavy": "aes-heavy",
            "heavy": "aes-heavy",
            "pb512": "aes-heavy",
            "aes512": "aes-heavy"
        }

        normalized = method_map.get(method)
        if not normalized:
            parser.error(f"Unsupported method '{args.method}'")

        if normalized == "b512":
            result = basefwx.b512file(args.paths, password, strip_metadata=args.strip_metadata, use_master=use_master)
        elif normalized == "aes-light":
            result = basefwx.AESfile(args.paths, password, light=True, strip_metadata=args.strip_metadata, use_master=use_master)
        else:
            result = basefwx.AESfile(args.paths, password, light=False, strip_metadata=args.strip_metadata, use_master=use_master)

        if isinstance(result, dict):
            failures = 0
            for path, status in result.items():
                print(f"{path}: {status}")
                if status != "SUCCESS!":
                    failures += 1
            return 0 if failures == 0 else 1

        print(result)
        return 0 if result == "SUCCESS!" else 1

    return 0


def main(argv=None) -> int:
    return cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
