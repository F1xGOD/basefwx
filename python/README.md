# basefwx (Python)

BaseFWX is a Python toolkit for encryption, encoding, and media/file transport workflows.

## Install

```bash
pip install basefwx
```

## Quick examples

```python
import basefwx

encrypted = basefwx.fwxAES_encrypt_raw(b"hello", "password")
plain = basefwx.fwxAES_decrypt_raw(encrypted, "password")

carrier = basefwx.kFMe("input.mp3", output="input.png", bw_mode=True)
restored = basefwx.kFMd(carrier, output="restored.mp3")
```

## Project links

- Repository: https://github.com/F1xGOD/basefwx
- Documentation: https://basefwx.fixcraft.jp/docs/PYTHON
