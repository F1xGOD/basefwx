# BASEFWX ENCRYPTION ENGINE ->

class basefwx:
    import base64
    import sys
    import secrets
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    import pathlib
    import os
    import hashlib
    import string
    def __init__(self):
        self.sys.set_int_max_str_digits(2000000000)
        pass

    @staticmethod
    def generate_random_string(length):
        """Generates a random string of the specified length."""
        self = basefwx()
        alphabet = self.string.ascii_letters + self.string.digits
        return ''.join(self.secrets.choice(alphabet) for i in range(length))

    @staticmethod
    def derive_key_from_text(text, salt, key_length_bytes=32):
        self = basefwx()
        """Derives an AES key from text using PBKDF2."""

        # Use PBKDF2 to derive a key from the text and salt
        key = self.hashlib.pbkdf2_hmac(
            "sha256",
            text.encode(),
            salt.encode(),
            100000,  # Number of iterations (higher is more secure)
            dklen=key_length_bytes
        )
        return key

    @staticmethod
    def encryptAES(text, key):
        self = basefwx()
        plaintext = text.encode('utf-8')
        key = basefwx.derive_key_from_text(key, str(basefwx.b512encode(key[:5], key)))

        # Generate a random initialization vector (IV)
        iv = self.os.urandom(16)

        # Create a cipher object
        cipher = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv))

        # Pad the plaintext to be a multiple of the block size
        padder = self.padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the plaintext
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return iv + ciphertext

    @staticmethod
    def decryptAES(text, key):
        ciphertext = text
        key = basefwx.derive_key_from_text(key, str(basefwx.b512encode(key[:5], key)))
        self = basefwx()
        # Extract the IV from the ciphertext
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]

        # Create a cipher object
        cipher = self.Cipher(self.algorithms.AES(key), self.modes.CBC(iv))

        # Decrypt the ciphertext
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the plaintext
        unpadder = self.padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode('utf-8')

    # REVERSIBLE  - SECURITY: ❙
    @staticmethod
    def b64encode(string: str):
        self = basefwx()
        return self.base64.b64encode(string.encode('utf-8')).decode('utf-8')

    @staticmethod
    def b64decode(string: str):
        self = basefwx()
        return self.base64.b64decode(string.encode('utf-8')).decode('utf-8')

    @staticmethod
    def hash512(string: str):
        self = basefwx()
        return self.hashlib.sha256(string.encode('utf-8')).hexdigest()

    @staticmethod
    def uhash513(string: str):
        self = basefwx()
        sti = string
        return self.hashlib.sha256(basefwx.b512encode(self.hashlib.sha512(
            self.hashlib.sha1(self.hashlib.sha256(sti.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest().encode(
                "utf-8")).hexdigest(), self.hashlib.sha512(sti.encode('utf-8')).hexdigest()).encode(
            'utf-8')).hexdigest()

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙
    @staticmethod
    def pb512encode(string: str, code: str):
        def encrypt_chunks_to_string(big_num_str: str, key_str: str) -> str:
            chunk_size = len(key_str)
            key_num = int(key_str)
            mod_val = 10 ** chunk_size

            # Record original length and pad the entire message to a multiple of chunk_size (right-padding)
            original_length = len(big_num_str)
            padded_length = ((original_length + chunk_size - 1) // chunk_size) * chunk_size
            padded_message = big_num_str.ljust(padded_length, '0')

            encrypted_chunks = []
            for i in range(0, padded_length, chunk_size):
                chunk = padded_message[i:i + chunk_size]
                chunk_val = int(chunk)
                # ENCRYPT: Add key and wrap-around using modulo
                encrypted_val = (chunk_val + key_num) % mod_val
                encrypted_chunks.append(str(encrypted_val).zfill(chunk_size))

            # Append a fixed-size header (10 digits) holding the original message length
            return ''.join(encrypted_chunks) + str(original_length).zfill(10)

        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        def mainenc(string):
            return str(encrypt_chunks_to_string(mdcode(string), mdcode(code)).replace("-", "0")).replace("=", "4G5tRA")

        return mainenc(string)

    @staticmethod
    def pb512decode(string: str, code: str):

        def decrypt_chunks_from_string(encrypted_str: str, key_str: str) -> str:
            chunk_size = len(key_str)
            key_num = int(key_str)
            mod_val = 10 ** chunk_size

            # Extract the header containing the original message length (last 10 digits)
            original_length = int(encrypted_str[-10:])
            encrypted_data = encrypted_str[:-10]

            decrypted_chunks = []
            for i in range(0, len(encrypted_data), chunk_size):
                chunk = encrypted_data[i:i + chunk_size]
                encrypted_val = int(chunk)
                # DECRYPT: Subtract key and wrap-around
                decrypted_val = (encrypted_val - key_num) % mod_val
                decrypted_chunks.append(str(decrypted_val).zfill(chunk_size))
            decrypted_padded = ''.join(decrypted_chunks)
            # Trim to the original message length
            return decrypted_padded[:original_length]

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
            string2 = string
            if string2[0] == "0":
                string2 = "-" + string2[1:len(string2)]
            result = mcode(decrypt_chunks_from_string(string2, mdcode(code)))

            return result

        return maindc(string)

    # REVERSIBLE CODE ENCODE - SECURITY: ❙❙
    @staticmethod
    def b512encode(string: str, code: str):
        self = basefwx()

        def encrypt_chunks_to_string(big_num_str: str, key_str: str) -> str:
            chunk_size = len(key_str)
            key_num = int(key_str)
            mod_val = 10 ** chunk_size

            # Record original length and pad the entire message to a multiple of chunk_size (right-padding)
            original_length = len(big_num_str)
            padded_length = ((original_length + chunk_size - 1) // chunk_size) * chunk_size
            padded_message = big_num_str.ljust(padded_length, '0')

            encrypted_chunks = []
            for i in range(0, padded_length, chunk_size):
                chunk = padded_message[i:i + chunk_size]
                chunk_val = int(chunk)
                # ENCRYPT: Add key and wrap-around using modulo
                encrypted_val = (chunk_val + key_num) % mod_val
                encrypted_chunks.append(str(encrypted_val).zfill(chunk_size))

            # Append a fixed-size header (10 digits) holding the original message length
            return ''.join(encrypted_chunks) + str(original_length).zfill(10)

        def fwx256bin(string):
            def code(string):
                mapping = {'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(', 'g': '*&GD2',
                           'h': '+*jsGA', 'i': '(aj*a', 'j': 'g%', 'k': '&G{A', 'l': '/IHa', 'm': '*(oa', 'n': '*KA^7',
                           'o': ')i*8A', 'p': '*H)PA-G', 'q': '*YFSA', 'r': 'O.-P[A', 's': '{9sl', 't': '*(HARR',
                           'u': 'O&iA6u', 'v': 'n):u', 'w': '&^F*GV', 'x': '(*HskW', 'y': '{JM', 'z': 'J.!dA',
                           'A': '(&Tav', 'B': 't5', 'C': '*TGA3', 'D': '*GABD', 'E': '{A', 'F': 'pW', 'G': '*UAK(',
                           'H': '&GH+', 'I': '&AN)', 'J': 'L&VA', 'K': '(HAF5', 'L': '&F*Va', 'M': '^&FVB',
                           'N': '(*HSA$i', 'O': '*IHda&gT', 'P': '&*FAl', 'Q': ')P{A]', 'R': '*Ha$g', 'S': 'G)OA&',
                           'T': '|QG6', 'U': 'Qd&^', 'V': 'hA', 'W': '8h^va', 'X': '_9xlA', 'Y': '*J', 'Z': '*;pY&',
                           ' ': 'R7a{', '-': '}F', '=': 'OJ)_A', '+': '}J', '&': '%A', '%': 'y{A3s', '#': '.aGa!',
                           '@': 'l@', '!': '/A', '^': 'OIp*a', '*': '(U', '(': 'I*Ua]', ')': '{0aD', '{': 'Av[',
                           '}': '9j', '[': '[a)', ']': '*&GBA', '|': ']Vc!A', '/': ')*HND_', '~': '(&*GHA',
                           ';': 'K}N=O', ':': 'YGOI&Ah', '?': 'Oa', '.': '8y)a', '>': '0{a9', '<': 'v6Yha',
                           ',': 'I8ys#', '0': '(HPA7', '1': '}v', '2': '*HAl%', '3': '_)JHS', '4': 'IG(A', '5': '(*GFD',
                           '6': 'IU(&V', '7': '(JH*G', '8': '*GHBA', '9': 'U&G*C', '\"': 'I(a-s'
                           }
                for char, replacement in mapping.items():
                    string = string.replace(char, replacement)
                return string

            return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')

        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        def mainenc(string):
            return fwx256bin(str(encrypt_chunks_to_string(mdcode(string), mdcode(code)).replace("-", "0"))).replace("=",
                                                                                                                    "4G5tRA")

        return mainenc(string)

    @staticmethod
    def b512decode(string: str, code: str):
        self = basefwx()

        def decrypt_chunks_from_string(encrypted_str: str, key_str: str) -> str:
            chunk_size = len(key_str)
            key_num = int(key_str)
            mod_val = 10 ** chunk_size

            # Extract the header containing the original message length (last 10 digits)
            original_length = int(encrypted_str[-10:])
            encrypted_data = encrypted_str[:-10]

            decrypted_chunks = []
            for i in range(0, len(encrypted_data), chunk_size):
                chunk = encrypted_data[i:i + chunk_size]
                encrypted_val = int(chunk)
                # DECRYPT: Subtract key and wrap-around
                decrypted_val = (encrypted_val - key_num) % mod_val
                decrypted_chunks.append(str(decrypted_val).zfill(chunk_size))
            decrypted_padded = ''.join(decrypted_chunks)
            # Trim to the original message length
            return decrypted_padded[:original_length]

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

        def fwx256unbin(string):
            def decode(sttr):
                mapping = {"I(a-s": "\"", "U&G*C": "9", "*GHBA": "8", "(JH*G": "7", "IU(&V": "6", "(*GFD": "5",
                           "IG(A": "4", "_)JHS": "3", "*HAl%": "2", "}v": "1", "(HPA7": "0", "I8ys#": ",", "v6Yha": "<",
                           "0{a9": ">", "8y)a": ".", "Oa": "?", "YGOI&Ah": ":", "K}N=O": ";", "(&*GHA": "~",
                           ")*HND_": "/", "]Vc!A": "|", "*&GBA": "]", "[a)": "[", "9j": "}", "Av[": "{", "{0aD": ")",
                           "I*Ua]": "(", "(U": "*", "OIp*a": "^", "/A": "!", "l@": "@", ".aGa!": "#", "y{A3s": "%",
                           "%A": "&", "}J": "+", "OJ)_A": "=", "}F": "-", "R7a{": " ", "*;pY&": "Z", "*J": "Y",
                           "_9xlA": "X", "8h^va": "W", "hA": "V", "Qd&^": "U", "|QG6": "T", "G)OA&": "S", "*Ha$g": "R",
                           ")P{A]": "Q", "&*FAl": "P", "*IHda&gT": "O", "(*HSA$i": "N", "^&FVB": "M", "&F*Va": "L",
                           "(HAF5": "K", "L&VA": "J", "&AN)": "I", "&GH+": "H", "*UAK(": "G", "pW": "F", "{A": "E",
                           "*GABD": "D", "*TGA3": "C", "t5": "B", "(&Tav": "A", "J.!dA": "z", "{JM": "y", "(*HskW": "x",
                           "&^F*GV": "w", "n):u": "v", "O&iA6u": "u", "*(HARR": "t", "{9sl": "s", "O.-P[A": "r",
                           "*YFSA": "q", "*H)PA-G": "p", ")i*8A": "o", "*KA^7": "n", "*(oa": "m", "/IHa": "l",
                           "&G{A": "k", "g%": "j", "(aj*a": "i", "+*jsGA": "h", "*&GD2": "g", "(*HGA(": "f",
                           "K5a{": "e", "*YHA": "d", "*&Gs": "c", "&hl": "b", "e*1": "a"}
                for key, value in mapping.items():
                    sttr = sttr.replace(key, value)
                return sttr

            return (decode(self.base64.b32hexdecode(string.encode('utf-8')).decode('utf-8')))

        def fwx256bin(string):
            def code(string):
                mapping = {'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(', 'g': '*&GD2',
                           'h': '+*jsGA', 'i': '(aj*a', 'j': 'g%', 'k': '&G{A', 'l': '/IHa', 'm': '*(oa', 'n': '*KA^7',
                           'o': ')i*8A', 'p': '*H)PA-G', 'q': '*YFSA', 'r': 'O.-P[A', 's': '{9sl', 't': '*(HARR',
                           'u': 'O&iA6u', 'v': 'n):u', 'w': '&^F*GV', 'x': '(*HskW', 'y': '{JM', 'z': 'J.!dA',
                           'A': '(&Tav', 'B': 't5', 'C': '*TGA3', 'D': '*GABD', 'E': '{A', 'F': 'pW', 'G': '*UAK(',
                           'H': '&GH+', 'I': '&AN)', 'J': 'L&VA', 'K': '(HAF5', 'L': '&F*Va', 'M': '^&FVB',
                           'N': '(*HSA$i', 'O': '*IHda&gT', 'P': '&*FAl', 'Q': ')P{A]', 'R': '*Ha$g', 'S': 'G)OA&',
                           'T': '|QG6', 'U': 'Qd&^', 'V': 'hA', 'W': '8h^va', 'X': '_9xlA', 'Y': '*J', 'Z': '*;pY&',
                           ' ': 'R7a{', '-': '}F', '=': 'OJ)_A', '+': '}J', '&': '%A', '%': 'y{A3s', '#': '.aGa!',
                           '@': 'l@', '!': '/A', '^': 'OIp*a', '*': '(U', '(': 'I*Ua]', ')': '{0aD', '{': 'Av[',
                           '}': '9j', '[': '[a)', ']': '*&GBA', '|': ']Vc!A', '/': ')*HND_', '~': '(&*GHA',
                           ';': 'K}N=O', ':': 'YGOI&Ah', '?': 'Oa', '.': '8y)a', '>': '0{a9', '<': 'v6Yha',
                           ',': 'I8ys#', '0': '(HPA7', '1': '}v', '2': '*HAl%', '3': '_)JHS', '4': 'IG(A', '5': '(*GFD',
                           '6': 'IU(&V', '7': '(JH*G', '8': '*GHBA', '9': 'U&G*C', '\"': 'I(a-s'
                           }
                for char, replacement in mapping.items():
                    string = string.replace(char, replacement)
                return string

            return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')

        def maindc(string):
            result = ""
            string2 = fwx256unbin(string.replace("4G5tRA", "="))
            if string2[0] == "0":
                string2 = "-" + string2[1:len(string2)]
            result = mcode(decrypt_chunks_from_string(string2, mdcode(code)))

            return result

        return maindc(string)

        # REVERSIBLE CODE ENCODE - SECURITY: ❙❙

    @staticmethod
    def b512file_encode(file: str, code: str):
        self = basefwx()

        def read(file: str):
            with open(file, 'rb') as file:
                return file.read()

        def encode(file: str, code: str):
            ext = basefwx.b512encode(self.pathlib.Path(file).suffix, code)
            en = str(basefwx.b512encode(self.base64.b64encode(read(file)).decode('utf-8'), code))
            return ext + "A8igTOmG" + en

        def write_fl(nm, cont):
            with open(nm + ".fwx", 'wb'):
                pass
            with open(nm + ".fwx", 'r+b') as f:
                f.write(cont.encode('utf-8'))
                f.close()

        def make_encoded(name, cd):
            write_fl(self.pathlib.Path(name).stem, encode(name, cd))
            self.os.chmod(self.pathlib.Path(self.pathlib.Path(name).stem + ".fwx"), 0)
            self.os.remove(self.pathlib.Path(self.pathlib.Path(name)))

        try:
            make_encoded(file, code)
            return "SUCCESS!"
        except:
            return "FAIL!"

    @staticmethod
    def b512file(file: str, password: str):
        self = basefwx()

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
            ext = basefwx.b512encode(self.pathlib.Path(file).suffix, code)
            en = str(basefwx.b512encode(self.base64.b64encode(read(file)).decode('utf-8'), code))
            return ext + "A8igTOmG" + en

        def decode(content: str, code: str):
            extd = basefwx.b512decode(content.split("A8igTOmG")[0], code)
            return [self.base64.b64decode(basefwx.b512decode(content.split("A8igTOmG")[1], code)), extd]

        def write_fl(nm, cont):
            with open(nm + ".fwx", 'wb'):
                pass
            with open(nm + ".fwx", 'r+b') as f:
                f.write(cont.encode('utf-8'))
                f.close()

        def make_decoded(name, cd):
            self.os.chmod(self.pathlib.Path(name), 0o777)
            try:
                ct = read_normal(self.pathlib.Path(name).stem + ".fwx")
                write(self.pathlib.Path(name).stem + decode(ct, cd)[1], decode(ct, cd)[0])
                self.os.remove(self.pathlib.Path(name))
            except:
                self.os.chmod(self.pathlib.Path(name), 0)
                print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                return "FAIL!"

        def make_encoded(name, cd):
            write_fl(self.pathlib.Path(name).stem, encode(name, cd))
            self.os.chmod(self.pathlib.Path(self.pathlib.Path(name).stem + ".fwx"), 0)
            self.os.remove(self.pathlib.Path(self.pathlib.Path(name)))
            return "SUCCESS!"

        if not self.os.path.isfile(file):
            print("\nFile Does Not Seem To Exist!")
            exit("-1")
        if self.pathlib.Path(file).suffix == ".fwx":
            v = make_decoded(file, password)
        else:
            v = make_encoded(file, password)
        return v

    @staticmethod
    def AESfile(file: str, password: str, light: bool = True):
        self = basefwx()
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
                ext = self.pathlib.Path(file).suffix
                en = str(self.base64.b64encode(read(file)).decode('utf-8'))
                return basefwx.encryptAES(ext + "A8igTOmG" + en, code)

            def decode(content: str, code: str):
                content = basefwx.decryptAES(content, code)
                extd = content.split("A8igTOmG")[0]
                return [self.base64.b64decode(content.split("A8igTOmG")[1]), extd]

            def write_fl(nm, cont):
                with open(nm + ".fwx", 'wb'):
                    pass
                with open(nm + ".fwx", 'r+b') as f:
                    f.write(cont)
                    f.close()

            def make_decoded(name, cd):
                self.os.chmod(self.pathlib.Path(name), 0o777)
                try:
                    ct = read_normal(self.pathlib.Path(name).stem + ".fwx")
                    write(self.pathlib.Path(name).stem + decode(ct, cd)[1], decode(ct, cd)[0])
                    self.os.remove(self.pathlib.Path(name))
                except:
                    self.os.chmod(self.pathlib.Path(name), 0)
                    print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                    return "FAIL!"

            def make_encoded(name, cd):
                write_fl(self.pathlib.Path(name).stem, encode(name, cd))
                self.os.chmod(self.pathlib.Path(self.pathlib.Path(name).stem + ".fwx"), 0)
                self.os.remove(self.pathlib.Path(self.pathlib.Path(name)))
                return "SUCCESS!"

            if not self.os.path.isfile(file):
                print("\nFile Does Not Seem To Exist!")
                exit("-1")
            if self.pathlib.Path(file).suffix == ".fwx":
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
                ext = basefwx.pb512encode(self.pathlib.Path(file).suffix, code)
                en = str(basefwx.pb512encode(self.base64.b64encode(read(file)).decode('utf-8'), code))
                return basefwx.encryptAES(ext + "673827837628292873" + en, code)

            def decode(content: str, code: str):
                content = basefwx.decryptAES(content, code)
                extd = content.split("673827837628292873")[0]
                return [self.base64.b64decode(basefwx.pb512decode(content.split("673827837628292873")[1], code)),
                        basefwx.pb512decode(extd, code)]

            def write_fl(nm, cont):
                with open(nm + ".fwx", 'wb'):
                    pass
                with open(nm + ".fwx", 'r+b') as f:
                    f.write(cont)
                    f.close()

            def make_decoded(name, cd):
                self.os.chmod(self.pathlib.Path(name), 0o777)
                try:
                    ct = read_normal(self.pathlib.Path(name).stem + ".fwx")
                    write(self.pathlib.Path(name).stem + decode(ct, cd)[1], decode(ct, cd)[0])
                    self.os.remove(self.pathlib.Path(name))
                except:
                    self.os.chmod(self.pathlib.Path(name), 0)
                    print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
                    return "FAIL!"

            def make_encoded(name, cd):
                write_fl(self.pathlib.Path(name).stem, encode(name, cd))
                self.os.chmod(self.pathlib.Path(self.pathlib.Path(name).stem + ".fwx"), 0)
                self.os.remove(self.pathlib.Path(self.pathlib.Path(name)))
                return "SUCCESS!"

            if not self.os.path.isfile(file):
                print("\nFile Does Not Seem To Exist!")
                exit("-1")
            if self.pathlib.Path(file).suffix == ".fwx":
                v = make_decoded(file, password)
            else:
                v = make_encoded(file, password)
            return v

    @staticmethod
    def b512file_decode(file: str, code: str):
        self = basefwx()

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
            return [self.base64.b64decode(basefwx.b512decode(content.split("A8igTOmG")[1], code)), extd]

        def make_decoded(name, cd):
            self.os.chmod(self.pathlib.Path(name), 0o777)
            ct = read_normal(self.pathlib.Path(name).stem + ".fwx")
            write(self.pathlib.Path(name).stem + decode(ct, cd)[1], decode(ct, cd)[0])
            self.os.remove(self.pathlib.Path(name))

        try:
            make_decoded(file, code)
            return "SUCCESS!"
        except:
            self.os.chmod(self.pathlib.Path(self.pathlib.Path(file).stem + ".fwx"), 0)
            return "FAIL!"

        # IRREVERSIBLE CODELESS ENCODE - SECURITY: ❙❙❙

    @staticmethod
    def bi512encode(string: str):
        self = basefwx()
        code = string[0] + string[len(string) - 1]

        def fwx256bin(string):
            def code(string):
                mapping = {'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(', 'g': '*&GD2',
                           'h': '+*jsGA', 'i': '(aj*a', 'j': 'g%', 'k': '&G{A', 'l': '/IHa', 'm': '*(oa', 'n': '*KA^7',
                           'o': ')i*8A', 'p': '*H)PA-G', 'q': '*YFSA', 'r': 'O.-P[A', 's': '{9sl', 't': '*(HARR',
                           'u': 'O&iA6u', 'v': 'n):u', 'w': '&^F*GV', 'x': '(*HskW', 'y': '{JM', 'z': 'J.!dA',
                           'A': '(&Tav', 'B': 't5', 'C': '*TGA3', 'D': '*GABD', 'E': '{A', 'F': 'pW', 'G': '*UAK(',
                           'H': '&GH+', 'I': '&AN)', 'J': 'L&VA', 'K': '(HAF5', 'L': '&F*Va', 'M': '^&FVB',
                           'N': '(*HSA$i', 'O': '*IHda&gT', 'P': '&*FAl', 'Q': ')P{A]', 'R': '*Ha$g', 'S': 'G)OA&',
                           'T': '|QG6', 'U': 'Qd&^', 'V': 'hA', 'W': '8h^va', 'X': '_9xlA', 'Y': '*J', 'Z': '*;pY&',
                           ' ': 'R7a{', '-': '}F', '=': 'OJ)_A', '+': '}J', '&': '%A', '%': 'y{A3s', '#': '.aGa!',
                           '@': 'l@', '!': '/A', '^': 'OIp*a', '*': '(U', '(': 'I*Ua]', ')': '{0aD', '{': 'Av[',
                           '}': '9j', '[': '[a)', ']': '*&GBA', '|': ']Vc!A', '/': ')*HND_', '~': '(&*GHA',
                           ';': 'K}N=O', ':': 'YGOI&Ah', '?': 'Oa', '.': '8y)a', '>': '0{a9', '<': 'v6Yha',
                           ',': 'I8ys#', '0': '(HPA7', '1': '}v', '2': '*HAl%', '3': '_)JHS', '4': 'IG(A', '5': '(*GFD',
                           '6': 'IU(&V', '7': '(JH*G', '8': '*GHBA', '9': 'U&G*C', '\"': 'I(a-s'
                           }
                for char, replacement in mapping.items():
                    string = string.replace(char, replacement)
                return string

            return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')

        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        def mainenc(string):
            return str(self.hashlib.sha256((fwx256bin(
                str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")).encode(
                'utf-8')).hexdigest()).replace("-", "0")

        return mainenc(string)

    # CODELESS ENCODE - SECURITY: ❙
    @staticmethod
    def a512encode(string: str):
        self = basefwx()

        def fwx256bin(string):
            def code(string):
                mapping = {'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(', 'g': '*&GD2',
                           'h': '+*jsGA', 'i': '(aj*a', 'j': 'g%', 'k': '&G{A', 'l': '/IHa', 'm': '*(oa', 'n': '*KA^7',
                           'o': ')i*8A', 'p': '*H)PA-G', 'q': '*YFSA', 'r': 'O.-P[A', 's': '{9sl', 't': '*(HARR',
                           'u': 'O&iA6u', 'v': 'n):u', 'w': '&^F*GV', 'x': '(*HskW', 'y': '{JM', 'z': 'J.!dA',
                           'A': '(&Tav', 'B': 't5', 'C': '*TGA3', 'D': '*GABD', 'E': '{A', 'F': 'pW', 'G': '*UAK(',
                           'H': '&GH+', 'I': '&AN)', 'J': 'L&VA', 'K': '(HAF5', 'L': '&F*Va', 'M': '^&FVB',
                           'N': '(*HSA$i', 'O': '*IHda&gT', 'P': '&*FAl', 'Q': ')P{A]', 'R': '*Ha$g', 'S': 'G)OA&',
                           'T': '|QG6', 'U': 'Qd&^', 'V': 'hA', 'W': '8h^va', 'X': '_9xlA', 'Y': '*J', 'Z': '*;pY&',
                           ' ': 'R7a{', '-': '}F', '=': 'OJ)_A', '+': '}J', '&': '%A', '%': 'y{A3s', '#': '.aGa!',
                           '@': 'l@', '!': '/A', '^': 'OIp*a', '*': '(U', '(': 'I*Ua]', ')': '{0aD', '{': 'Av[',
                           '}': '9j', '[': '[a)', ']': '*&GBA', '|': ']Vc!A', '/': ')*HND_', '~': '(&*GHA',
                           ';': 'K}N=O', ':': 'YGOI&Ah', '?': 'Oa', '.': '8y)a', '>': '0{a9', '<': 'v6Yha',
                           ',': 'I8ys#', '0': '(HPA7', '1': '}v', '2': '*HAl%', '3': '_)JHS', '4': 'IG(A', '5': '(*GFD',
                           '6': 'IU(&V', '7': '(JH*G', '8': '*GHBA', '9': 'U&G*C', '\"': 'I(a-s'
                           }
                for char, replacement in mapping.items():
                    string = string.replace(char, replacement)
                return string

            return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')

        def mdcode(string: str):
            st = str(string)
            binaryvals = map(bin, bytearray(st.encode('ascii')))
            end = ""
            for bb in binaryvals:
                end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
            return str(end)

        code = (str(len(mdcode((string))) * len(mdcode((string)))))

        def mainenc(string):
            return str(len(str(len(mdcode(string))))) + str(len(mdcode(string))) + fwx256bin(
                str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")

        return mainenc(string)

    @staticmethod
    def a512decode(string: str):
        self = basefwx()

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

        def fwx256unbin(string):
            def decode(sttr):
                mapping = {"I(a-s": "\"", "U&G*C": "9", "*GHBA": "8", "(JH*G": "7", "IU(&V": "6", "(*GFD": "5",
                           "IG(A": "4", "_)JHS": "3", "*HAl%": "2", "}v": "1", "(HPA7": "0", "I8ys#": ",", "v6Yha": "<",
                           "0{a9": ">", "8y)a": ".", "Oa": "?", "YGOI&Ah": ":", "K}N=O": ";", "(&*GHA": "~",
                           ")*HND_": "/", "]Vc!A": "|", "*&GBA": "]", "[a)": "[", "9j": "}", "Av[": "{", "{0aD": ")",
                           "I*Ua]": "(", "(U": "*", "OIp*a": "^", "/A": "!", "l@": "@", ".aGa!": "#", "y{A3s": "%",
                           "%A": "&", "}J": "+", "OJ)_A": "=", "}F": "-", "R7a{": " ", "*;pY&": "Z", "*J": "Y",
                           "_9xlA": "X", "8h^va": "W", "hA": "V", "Qd&^": "U", "|QG6": "T", "G)OA&": "S", "*Ha$g": "R",
                           ")P{A]": "Q", "&*FAl": "P", "*IHda&gT": "O", "(*HSA$i": "N", "^&FVB": "M", "&F*Va": "L",
                           "(HAF5": "K", "L&VA": "J", "&AN)": "I", "&GH+": "H", "*UAK(": "G", "pW": "F", "{A": "E",
                           "*GABD": "D", "*TGA3": "C", "t5": "B", "(&Tav": "A", "J.!dA": "z", "{JM": "y", "(*HskW": "x",
                           "&^F*GV": "w", "n):u": "v", "O&iA6u": "u", "*(HARR": "t", "{9sl": "s", "O.-P[A": "r",
                           "*YFSA": "q", "*H)PA-G": "p", ")i*8A": "o", "*KA^7": "n", "*(oa": "m", "/IHa": "l",
                           "&G{A": "k", "g%": "j", "(aj*a": "i", "+*jsGA": "h", "*&GD2": "g", "(*HGA(": "f",
                           "K5a{": "e", "*YHA": "d", "*&Gs": "c", "&hl": "b", "e*1": "a"}
                for key, value in mapping.items():
                    sttr = sttr.replace(key, value)
                return sttr

            return (decode(self.base64.b32hexdecode(string.encode('utf-8')).decode('utf-8')))

        def fwx256bin(string):
            def code(string):
                mapping = {'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(', 'g': '*&GD2',
                           'h': '+*jsGA', 'i': '(aj*a', 'j': 'g%', 'k': '&G{A', 'l': '/IHa', 'm': '*(oa', 'n': '*KA^7',
                           'o': ')i*8A', 'p': '*H)PA-G', 'q': '*YFSA', 'r': 'O.-P[A', 's': '{9sl', 't': '*(HARR',
                           'u': 'O&iA6u', 'v': 'n):u', 'w': '&^F*GV', 'x': '(*HskW', 'y': '{JM', 'z': 'J.!dA',
                           'A': '(&Tav', 'B': 't5', 'C': '*TGA3', 'D': '*GABD', 'E': '{A', 'F': 'pW', 'G': '*UAK(',
                           'H': '&GH+', 'I': '&AN)', 'J': 'L&VA', 'K': '(HAF5', 'L': '&F*Va', 'M': '^&FVB',
                           'N': '(*HSA$i', 'O': '*IHda&gT', 'P': '&*FAl', 'Q': ')P{A]', 'R': '*Ha$g', 'S': 'G)OA&',
                           'T': '|QG6', 'U': 'Qd&^', 'V': 'hA', 'W': '8h^va', 'X': '_9xlA', 'Y': '*J', 'Z': '*;pY&',
                           ' ': 'R7a{', '-': '}F', '=': 'OJ)_A', '+': '}J', '&': '%A', '%': 'y{A3s', '#': '.aGa!',
                           '@': 'l@', '!': '/A', '^': 'OIp*a', '*': '(U', '(': 'I*Ua]', ')': '{0aD', '{': 'Av[',
                           '}': '9j', '[': '[a)', ']': '*&GBA', '|': ']Vc!A', '/': ')*HND_', '~': '(&*GHA',
                           ';': 'K}N=O', ':': 'YGOI&Ah', '?': 'Oa', '.': '8y)a', '>': '0{a9', '<': 'v6Yha',
                           ',': 'I8ys#', '0': '(HPA7', '1': '}v', '2': '*HAl%', '3': '_)JHS', '4': 'IG(A', '5': '(*GFD',
                           '6': 'IU(&V', '7': '(JH*G', '8': '*GHBA', '9': 'U&G*C', '\"': 'I(a-s'
                           }
                for char, replacement in mapping.items():
                    string = string.replace(char, replacement)
                return string

            return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')

        def maindc(string):
            result = ""
            try:
                leoa = int(string[0])
                string2 = string[leoa + 1:len(string)]
                cdo = int(string[1:leoa + 1]) * int(string[1:leoa + 1])
                code = (str(cdo))
                string3 = fwx256unbin(string2.replace("4G5tRA", "="))
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
        self = basefwx()

        def fwx1024uBIN(string: str):
            def fwx512iiBIN(string: str):
                code = string[0] + string[len(string) - 1]

                def fwx256bin(string):
                    def code(string):
                        mapping = {'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(',
                                   'g': '*&GD2', 'h': '+*jsGA', 'i': '(aj*a', 'j': 'g%', 'k': '&G{A', 'l': '/IHa',
                                   'm': '*(oa', 'n': '*KA^7', 'o': ')i*8A', 'p': '*H)PA-G', 'q': '*YFSA', 'r': 'O.-P[A',
                                   's': '{9sl', 't': '*(HARR', 'u': 'O&iA6u', 'v': 'n):u', 'w': '&^F*GV', 'x': '(*HskW',
                                   'y': '{JM', 'z': 'J.!dA', 'A': '(&Tav', 'B': 't5', 'C': '*TGA3', 'D': '*GABD',
                                   'E': '{A', 'F': 'pW', 'G': '*UAK(', 'H': '&GH+', 'I': '&AN)', 'J': 'L&VA',
                                   'K': '(HAF5', 'L': '&F*Va', 'M': '^&FVB', 'N': '(*HSA$i', 'O': '*IHda&gT',
                                   'P': '&*FAl', 'Q': ')P{A]', 'R': '*Ha$g', 'S': 'G)OA&', 'T': '|QG6', 'U': 'Qd&^',
                                   'V': 'hA', 'W': '8h^va', 'X': '_9xlA', 'Y': '*J', 'Z': '*;pY&', ' ': 'R7a{',
                                   '-': '}F', '=': 'OJ)_A', '+': '}J', '&': '%A', '%': 'y{A3s', '#': '.aGa!', '@': 'l@',
                                   '!': '/A', '^': 'OIp*a', '*': '(U', '(': 'I*Ua]', ')': '{0aD', '{': 'Av[', '}': '9j',
                                   '[': '[a)', ']': '*&GBA', '|': ']Vc!A', '/': ')*HND_', '~': '(&*GHA', ';': 'K}N=O',
                                   ':': 'YGOI&Ah', '?': 'Oa', '.': '8y)a', '>': '0{a9', '<': 'v6Yha', ',': 'I8ys#',
                                   '0': '(HPA7', '1': '}v', '2': '*HAl%', '3': '_)JHS', '4': 'IG(A', '5': '(*GFD',
                                   '6': 'IU(&V', '7': '(JH*G', '8': '*GHBA', '9': 'U&G*C', '\"': 'I(a-s'
                                   }
                        for char, replacement in mapping.items():
                            string = string.replace(char, replacement)
                        return string

                    return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')

                def mdcode(string: str):
                    st = str(string)
                    binaryvals = map(bin, bytearray(st.encode('ascii')))
                    end = ""
                    for bb in binaryvals:
                        end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
                    return str(end)

                def mainenc(string):
                    return str(self.hashlib.sha256((fwx256bin(
                        str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=",
                                                                                                         "4G5tRA")).encode(
                        'utf-8')).hexdigest()).replace("-", "0")

                return mainenc(string)

            def fwx512ciBIN(string: str):
                def fwx256bin(string):
                    def code(string):
                        mapping = {'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(',
                                   'g': '*&GD2', 'h': '+*jsGA', 'i': '(aj*a', 'j': 'g%', 'k': '&G{A', 'l': '/IHa',
                                   'm': '*(oa', 'n': '*KA^7', 'o': ')i*8A', 'p': '*H)PA-G', 'q': '*YFSA', 'r': 'O.-P[A',
                                   's': '{9sl', 't': '*(HARR', 'u': 'O&iA6u', 'v': 'n):u', 'w': '&^F*GV', 'x': '(*HskW',
                                   'y': '{JM', 'z': 'J.!dA', 'A': '(&Tav', 'B': 't5', 'C': '*TGA3', 'D': '*GABD',
                                   'E': '{A', 'F': 'pW', 'G': '*UAK(', 'H': '&GH+', 'I': '&AN)', 'J': 'L&VA',
                                   'K': '(HAF5', 'L': '&F*Va', 'M': '^&FVB', 'N': '(*HSA$i', 'O': '*IHda&gT',
                                   'P': '&*FAl', 'Q': ')P{A]', 'R': '*Ha$g', 'S': 'G)OA&', 'T': '|QG6', 'U': 'Qd&^',
                                   'V': 'hA', 'W': '8h^va', 'X': '_9xlA', 'Y': '*J', 'Z': '*;pY&', ' ': 'R7a{',
                                   '-': '}F', '=': 'OJ)_A', '+': '}J', '&': '%A', '%': 'y{A3s', '#': '.aGa!', '@': 'l@',
                                   '!': '/A', '^': 'OIp*a', '*': '(U', '(': 'I*Ua]', ')': '{0aD', '{': 'Av[', '}': '9j',
                                   '[': '[a)', ']': '*&GBA', '|': ']Vc!A', '/': ')*HND_', '~': '(&*GHA', ';': 'K}N=O',
                                   ':': 'YGOI&Ah', '?': 'Oa', '.': '8y)a', '>': '0{a9', '<': 'v6Yha', ',': 'I8ys#',
                                   '0': '(HPA7', '1': '}v', '2': '*HAl%', '3': '_)JHS', '4': 'IG(A', '5': '(*GFD',
                                   '6': 'IU(&V', '7': '(JH*G', '8': '*GHBA', '9': 'U&G*C', '\"': 'I(a-s'
                                   }
                        for char, replacement in mapping.items():
                            string = string.replace(char, replacement)
                        return string

                    return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')

                def mdcode(string: str):
                    st = str(string)
                    binaryvals = map(bin, bytearray(st.encode('ascii')))
                    end = ""
                    for bb in binaryvals:
                        end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
                    return str(end)

                code = (str(len(mdcode((string))) * len(mdcode((string)))))

                def mainenc(string):
                    return str(len(str(len(mdcode(string))))) + str(len(mdcode(string))) + fwx256bin(
                        str((str(int(mdcode((string))) - int(mdcode(code))).replace("-", "0")))).replace("=", "4G5tRA")

                return mainenc(string)

            return fwx512iiBIN(fwx512ciBIN(string))

        return fwx1024uBIN(string)

    # CODELESS ENCODE - SECURITY: ❙
    @staticmethod
    def b256decode(string):
        self = basefwx()

        def decode(sttr):
            mapping = {"I(a-s": "\"", "U&G*C": "9", "*GHBA": "8", "(JH*G": "7", "IU(&V": "6", "(*GFD": "5", "IG(A": "4",
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
                       "e*1": "a"}
            for key, value in mapping.items():
                sttr = sttr.replace(key, value)
            return sttr

        return (decode(self.base64.b32hexdecode(string.encode('utf-8')).decode('utf-8')))

    @staticmethod
    def b256encode(string):
        self = basefwx()

        def code(string):
            mapping = {'a': 'e*1', 'b': '&hl', 'c': '*&Gs', 'd': '*YHA', 'e': 'K5a{', 'f': '(*HGA(', 'g': '*&GD2',
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
                       '9': 'U&G*C', '\"': 'I(a-s'
                       }
            for char, replacement in mapping.items():
                string = string.replace(char, replacement)
            return string

        return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')

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

# HOW TO USE: basefwx.ENCRTPTION-TYPE("text","password")
