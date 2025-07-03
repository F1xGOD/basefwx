# BASEFWX ENCRYPTION ENGINE ->

class basefwx:
    import base64
    import sys
    import secrets
    import pathlib
    import random
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
    def encryptAES(plaintext: str, user_key: str) -> bytes:
        if user_key=="":
            if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                user_key = basefwx.os.path.expanduser("~/master.pem")
            elif basefwx.os.path.exists("W:\\master.pem"):
                user_key = "W:\\master.pem"
            else:
                print("Failed To Encode File, The Key File Is Corrupted!")
                basefwx.sys.exit(1)
        basefwx.sys.set_int_max_str_digits(2000000000)
        ephemeral_key = basefwx.os.urandom(32)
        user_derived_key = basefwx._derive_user_key(user_key)
        ephemeral_key_b64 = basefwx.base64.b64encode(ephemeral_key).decode('utf-8')
        iv_user = basefwx.os.urandom(16)
        cipher_user = basefwx.Cipher(basefwx.algorithms.AES(user_derived_key), basefwx.modes.CBC(iv_user))
        encryptor_user = cipher_user.encryptor()
        keypem = basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk))
        padder = basefwx.padding.PKCS7(128).padder()
        padded_ephemeral_key = padder.update(ephemeral_key_b64.encode('utf-8')) + padder.finalize()
        ephemeral_enc_user = encryptor_user.update(padded_ephemeral_key) + encryptor_user.finalize()
        ephemeral_enc_user = iv_user + ephemeral_enc_user
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
        iv_data = basefwx.os.urandom(16)
        cipher_data = basefwx.Cipher(basefwx.algorithms.AES(ephemeral_key), basefwx.modes.CBC(iv_data))
        encryptor_data = cipher_data.encryptor()
        padder2 = basefwx.padding.PKCS7(128).padder()
        padded_plaintext = padder2.update(plaintext.encode('utf-8')) + padder2.finalize()
        ciphertext = encryptor_data.update(padded_plaintext) + encryptor_data.finalize()
        ciphertext = iv_data + ciphertext
        def int_to_4(i): return i.to_bytes(4, byteorder='big', signed=False)
        blob = b''
        blob += int_to_4(len(ephemeral_enc_user)) + ephemeral_enc_user
        blob += int_to_4(len(ephemeral_enc_master)) + ephemeral_enc_master
        blob += int_to_4(len(ciphertext)) + ciphertext
        return blob

    @staticmethod
    def decryptAES(encrypted_blob: bytes, key: str="") -> str:
        basefwx.sys.set_int_max_str_digits(2000000000)
        if key=="":
            if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                key = basefwx.os.path.expanduser("~/master.pem")
            elif basefwx.os.path.exists("W:\\master.pem"):
                key = "W:\\master.pem"
            else:
                print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                basefwx.sys.exit(1)
        def read_chunk(in_bytes, offset):
            length = int.from_bytes(in_bytes[offset:offset+4], 'big')
            offset += 4
            chunk = in_bytes[offset:offset+length]
            offset += length
            return chunk, offset
        offset = 0
        ephemeral_enc_user, offset = read_chunk(encrypted_blob, offset)
        ephemeral_enc_master, offset = read_chunk(encrypted_blob, offset)
        ciphertext, offset = read_chunk(encrypted_blob, offset)
        ephemeral_key = None
        if basefwx.os.path.isfile(key):
            with open(key, "rb") as f:
                private_key_data = f.read()
            private_key = basefwx.serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=basefwx.default_backend()
            )
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
    MASTERk=b'eJxdkkuPqkAUhPf3V7gnhqcCy25otEGbh4DIThpEXgMKCvLrZ+auLrdWJ1XJl5NUrdc/gmiHycoJ4AFrKwtdfr31n9U/OmIMcQkIzKvHvSp26shB4CIDAFsDrgJ+cy23fm4EtmMsqcqs7pFEKIu3XpMMC1g/2s2Zc3tyqfVDnAs3NhKTV/uR6qir77GgtW+nHXiYevAmPv1TwvLzMPM1tXRnfBnuAlZqVuTMjlyAsH0q1Hf84GNlVK25Zy5XGTNyU0GM7phwmnI1OTO2aRoKuCDpFCAwXhcw2aM5XwWkSx5Jt0NeCfYiAXfTG3JKQ2meh8yIxIzJ8pY5l/E2SGuHZG4hMh9L9oXlZw/cSxWkCPThJzoBeJRiGrKWhns/cp6tMqiCpLtmIyuI9yZjK79T6r8AKg/8JJyBuYClQokiZrOZNtFQGMY12diwsTw3uZ2b4fbep0Z8CDTVE62w+9qzEivOJ/PLO0n40l1kx17AdiPWgQvgwvxbOiL6/zv4BsbIl0s='
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
            basefwx.hashlib.sha1(basefwx.hashlib.sha256(sti.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest().encode(
                "utf-8")).hexdigest(), basefwx.hashlib.sha512(sti.encode('utf-8')).hexdigest()).encode(
            'utf-8')).hexdigest()

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙
    @staticmethod
    def pb512encode(t, p):
        if p == "":
            if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                p = open(basefwx.os.path.expanduser("~/master.pem")).read()
            elif basefwx.os.path.exists("W:\\master.pem"):
                p = open("W:\\master.pem").read()
            else:
                print("Failed To Encode File, The Key File Is Corrupted!")
                basefwx.sys.exit(1)
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
        keypem = basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk))
        ecu = iv1 + ecu
        pk = basefwx.serialization.load_pem_public_key(keypem, backend=basefwx.default_backend())
        ecm = pk.encrypt(c.encode('utf-8'),
                         basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),
                                                   algorithm=basefwx.hashes.SHA256(), label=None))

        def i4(x):
            return x.to_bytes(4, "big")

        blob = i4(len(ecu)) + ecu + i4(len(ecm)) + ecm + i4(len(cb)) + cb
        ln = len(blob)
        val = int.from_bytes(blob, 'big')
        return str(ln).zfill(6) + str(val)

    @staticmethod
    def pb512decode(digs, key):
        if key=="":
            if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                key = open(basefwx.os.path.expanduser("~/master.pem")).read()
            elif basefwx.os.path.exists("W:\\master.pem"):
                key = open("W:\\master.pem").read()
            else:
                print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                basefwx.sys.exit(1)
        k=key
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
        if "BEGIN PRIVATE KEY" in k:
            pk = basefwx.serialization.load_pem_private_key(k.encode('utf-8'), None, backend=basefwx.default_backend())
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
    def b512encode(string, user_key):
        if user_key == "":
            if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                user_key = open(basefwx.os.path.expanduser("~/master.pem")).read()
            elif basefwx.os.path.exists("W:\\master.pem"):
                user_key = open("W:\\master.pem").read()
            else:
                print("Failed To Encode File, The Key File Is Corrupted!")
                basefwx.sys.exit(1)
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

        keypem=basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk))

        pk = basefwx.serialization.load_pem_public_key(keypem, backend=basefwx.default_backend())
        epm = pk.encrypt(
            ep.encode('utf-8'),
            basefwx.asym_padding.OAEP(
                mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),
                algorithm=basefwx.hashes.SHA256(),
                label=None
            )
        )

        def i4(x):
            return x.to_bytes(4, 'big')

        blob = i4(len(epu)) + epu + i4(len(epm)) + epm + i4(len(ec_bin)) + ec_bin

        # Instead of decimal string => base64-encode the final bytes => return as a normal string
        return basefwx.base64.b64encode(blob).decode('utf-8')

    @staticmethod
    def b512decode(enc, key=""):
        if key == "":
            if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                key = open(basefwx.os.path.expanduser("~/master.pem")).read()
            elif basefwx.os.path.exists("W:\\master.pem"):
                key = open("W:\\master.pem").read()
            else:
                print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                basefwx.sys.exit(1)

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

        if "BEGIN PRIVATE KEY" in key:
            pk = basefwx.serialization.load_pem_private_key(
                key.encode('utf-8'),
                None,
                backend=basefwx.default_backend()
            )
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
    def b512file_encode(file: str, code: str):
        

        def read(file: str):
            with open(file, 'rb') as file:
                return file.read()

        def encode(file: str, code: str):
            ext = basefwx.b512encode(basefwx.pathlib.Path(file).suffix, code)
            en = str(basefwx.b512encode(basefwx.base64.b64encode(read(file)).decode('utf-8'), code))
            return ext + "A8igTOmG" + en

        def write_fl(nm, cont):
            with open(nm + ".fwx", 'wb'):
                pass
            with open(nm + ".fwx", 'r+b') as f:
                f.write(cont.encode('utf-8'))
                f.close()

        def make_encoded(name, cd):
            write_fl(basefwx.pathlib.Path(name).stem, encode(name, cd))
            basefwx.os.chmod(basefwx.pathlib.Path(basefwx.pathlib.Path(name).stem + ".fwx"), 0)
            basefwx.os.remove(basefwx.pathlib.Path(basefwx.pathlib.Path(name)))

        try:
            make_encoded(file, code)
            return "SUCCESS!"
        except:
            return "FAIL!"

    @staticmethod
    def b512file(file: str, password: str):
        if password == "":
            if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                password = basefwx.os.path.expanduser("~/master.pem")
            elif basefwx.os.path.exists("W:\\master.pem"):
                password = "W:\\master.pem"
            else:
                print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                basefwx.sys.exit(1)

        if basefwx.os.path.isfile(password):
            password = open(password, 'r').read()

        def read(file: str):
            with open(file, 'rb') as file:
                return file.read()

        def read_normal(file: str):
            with open(file, 'r') as fil:
                return fil.read()

        def write(file: str, content: bytes):
            with open(file, 'wb'):
                pass
            f = open(file, 'r+b')
            f.write(content)
            f.close()

        def encode(file: str, code: str):
            ext = basefwx.b512encode(basefwx.pathlib.Path(file).suffix, code)
            en = str(basefwx.b512encode(basefwx.base64.b64encode(read(file)).decode('utf-8'), code))
            return ext + "A8igTOmG" + en

        def decode(content: str, code: str):
            if "BEGIN PRIVATE KEY" in password:
                code = ""
            extd = basefwx.b512decode(content.split("A8igTOmG")[0], code)
            return [basefwx.base64.b64decode(basefwx.b512decode(content.split("A8igTOmG")[1], code)), extd]

        def write_fl(nm, cont):
            with open(nm + ".fwx", 'wb'):
                pass
            with open(nm + ".fwx", 'r+b') as f:
                f.write(cont.encode('utf-8'))
                f.close()

        def make_decoded(name, cd):
            basefwx.os.chmod(basefwx.pathlib.Path(name), 0o777)
            try:
                ct = read_normal(basefwx.pathlib.Path(name).stem + ".fwx")
                write(basefwx.pathlib.Path(name).stem + decode(ct, cd)[1], decode(ct, cd)[0])
                basefwx.os.remove(basefwx.pathlib.Path(name))
            except:
                basefwx.os.chmod(basefwx.pathlib.Path(name), 0)
                print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                return "FAIL!"

        def make_encoded(name, cd):
            write_fl(basefwx.pathlib.Path(name).stem, encode(name, cd))
            basefwx.os.chmod(basefwx.pathlib.Path(basefwx.pathlib.Path(name).stem + ".fwx"), 0)
            basefwx.os.remove(basefwx.pathlib.Path(basefwx.pathlib.Path(name)))
            return "SUCCESS!"

        if not basefwx.os.path.isfile(file):
            print("\nFile Does Not Seem To Exist!")
            exit("-1")
        if basefwx.pathlib.Path(file).suffix == ".fwx":
            v = make_decoded(file, password)
        else:
            v = make_encoded(file, password)
        return v

    @staticmethod
    def AESfile(file: str, password: str="", light: bool = True):
        basefwx.sys.set_int_max_str_digits(2000000000)
        if password == "":
            if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                password = basefwx.os.path.expanduser("~/master.pem")
            elif basefwx.os.path.exists("W:\\master.pem"):
                password = "W:\\master.pem"
            else:
                print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                basefwx.sys.exit(1)

        if basefwx.os.path.isfile(password):
            password = open(password, 'r').read()
        if light:
            def read(file: str):
                with open(file, 'rb') as file:
                    return file.read()

            def read_normal(file: str):
                with open(file, 'r+b') as fil:
                    return fil.read()

            def write(file: str, content: bytes):
                with open(file, 'wb'):
                    pass
                f = open(file, 'r+b')
                f.write(content)
                f.close()

            def encode(file: str, code: str):
                ext = basefwx.pathlib.Path(file).suffix
                en = str(basefwx.base64.b64encode(read(file)).decode('utf-8'))
                return basefwx.encryptAES(ext + "A8igTOmG" + en, code)

            def decode(content: bytes, code: str):
                if "BEGIN PRIVATE KEY" in password:
                    code=""
                content = basefwx.decryptAES(content, code)
                extd = content.split("A8igTOmG")[0]
                return [basefwx.base64.b64decode(content.split("A8igTOmG")[1]), extd]

            def write_fl(nm, cont):
                with open(nm + ".fwx", 'wb'):
                    pass
                with open(nm + ".fwx", 'r+b') as f:
                    f.write(cont)
                    f.close()

            def make_decoded(name, cd):
                basefwx.os.chmod(basefwx.pathlib.Path(name), 0o777)
                try:
                    ct = basefwx.zlib.decompress(read_normal(basefwx.pathlib.Path(name).stem + ".fwx"))
                    write(basefwx.pathlib.Path(name).stem + decode(ct, cd)[1], decode(ct, cd)[0])
                    basefwx.os.remove(basefwx.pathlib.Path(name))
                except:
                    basefwx.os.chmod(basefwx.pathlib.Path(name), 0)
                    print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                    return "FAIL!"

            def make_encoded(name, cd):
                write_fl(basefwx.pathlib.Path(name).stem, basefwx.zlib.compress(encode(name, cd)))
                basefwx.os.chmod(basefwx.pathlib.Path(basefwx.pathlib.Path(name).stem + ".fwx"), 0)
                basefwx.os.remove(basefwx.pathlib.Path(basefwx.pathlib.Path(name)))
                return "SUCCESS!"

            if not basefwx.os.path.isfile(file):
                print("\nFile Does Not Seem To Exist!")
                exit("-1")
            if basefwx.pathlib.Path(file).suffix == ".fwx":
                v = make_decoded(file, password)
            else:
                v = make_encoded(file, password)
            return v
        else:
            def read(file: str):
                with open(file, 'rb') as file:
                    return file.read()

            def read_normal(file: str):
                with open(file, 'r+b') as fil:
                    return fil.read()

            def write(file: str, content: bytes):
                with open(file, 'wb'):
                    pass
                f = open(file, 'r+b')
                f.write(content)
                f.close()

            def encode(file: str, code: str):
                ext = basefwx.pb512encode(basefwx.pathlib.Path(file).suffix, code)
                en = str(basefwx.pb512encode(basefwx.base64.b64encode(read(file)).decode('utf-8'), code))
                return basefwx.encryptAES(ext + "673827837628292873" + en, code)

            def decode(content: bytes, code: str):
                if "BEGIN PRIVATE KEY" in password:
                    code=""
                content = basefwx.decryptAES(content, code)
                extd = content.split("673827837628292873")[0]
                return [basefwx.base64.b64decode(basefwx.pb512decode(content.split("673827837628292873")[1], code)),
                        basefwx.pb512decode(extd, code)]

            def write_fl(nm, cont):
                with open(nm + ".fwx", 'wb'):
                    pass
                with open(nm + ".fwx", 'r+b') as f:
                    f.write(cont)
                    f.close()

            def make_decoded(name, cd):
                basefwx.os.chmod(basefwx.pathlib.Path(name), 0o777)
                try:
                    ct = read(basefwx.pathlib.Path(name).stem + ".fwx")
                    write(basefwx.pathlib.Path(name).stem + decode(ct, cd)[1], decode(ct, cd)[0])
                    basefwx.os.remove(basefwx.pathlib.Path(name))
                except:
                    basefwx.os.chmod(basefwx.pathlib.Path(name), 0)
                    print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                    return "FAIL!"

            def make_encoded(name, cd):
                write_fl(basefwx.pathlib.Path(name).stem, encode(name, cd))
                basefwx.os.chmod(basefwx.pathlib.Path(basefwx.pathlib.Path(name).stem + ".fwx"), 0)
                basefwx.os.remove(basefwx.pathlib.Path(basefwx.pathlib.Path(name)))
                return "SUCCESS!"

            if not basefwx.os.path.isfile(file):
                print("\nFile Does Not Seem To Exist!")
                exit("-1")
            if basefwx.pathlib.Path(file).suffix == ".fwx":
                v = make_decoded(file, password)
            else:
                v = make_encoded(file, password)
            return v

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
    def b512file_decode(file: str, code: str):
        if code == "":
            if basefwx.os.path.exists(basefwx.os.path.expanduser("~/master.pem")):
                code = basefwx.os.path.expanduser("~/master.pem")
            elif basefwx.os.path.exists("W:\\master.pem"):
                code = "W:\\master.pem"
            else:
                print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                basefwx.sys.exit(1)

        # MINIMAL FIX: if 'code' is a file path, load the PEM content into 'code'
        if basefwx.os.path.isfile(code):
            code = open(code, 'r').read()

        def read_normal(file: str):
            with open(file, 'r') as fil:
                return fil.read()

        def write(file: str, content: bytes):
            with open(file, 'wb'):
                pass
            f = open(file, 'r+b')
            f.write(content)
            f.close()

        def decode(content: str, code: str):
            extd = basefwx.b512decode(content.split("A8igTOmG")[0], code)
            return [basefwx.base64.b64decode(basefwx.b512decode(content.split("A8igTOmG")[1], code)), extd]

        def make_decoded(name, cd):
            basefwx.os.chmod(basefwx.pathlib.Path(name), 0o777)
            ct = read_normal(basefwx.pathlib.Path(name).stem + ".fwx")
            write(basefwx.pathlib.Path(name).stem + decode(ct, cd)[1], decode(ct, cd)[0])
            basefwx.os.remove(basefwx.pathlib.Path(name))

        try:
            make_decoded(file, code)
            return "SUCCESS!"
        except:
            basefwx.os.chmod(basefwx.pathlib.Path(basefwx.pathlib.Path(file).stem + ".fwx"), 0)
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
