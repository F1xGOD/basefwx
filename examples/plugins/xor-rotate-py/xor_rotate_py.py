# BaseFWX example plugin
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0, with the
# BaseFWX Plugin-Template Exception (see LICENCE clause 5).
# You may use this file as a starting template for your own
# Plugin under any license your Plugin chooses.


from basefwx.plugin import (
    BasefwxPlugin,
    PluginErrorBadInput,
    Position,
)


class XorRotatePy(BasefwxPlugin):
    # 8d4c2a01-1f70-4d3a-91ab-2c5e8f917b04 — SAME id as the C++
    # example, so a corpus encoded with PyXorRotate decodes cleanly
    # under the C++ plugin and vice versa (the byte transforms are
    # identical).
    PLUGIN_ID = bytes.fromhex("8d4c2a011f704d3a91ab2c5e8f917b04")
    NAME = "xor-rotate-py"
    VERSION = "1.0.0"
    SUPPORTED_POSITIONS = int(Position.PRE_AEAD | Position.POST_AEAD)

    KEY_LEN = 32

    def __init__(self, config: bytes = b""):
        super().__init__(config=config)
        if config is None or len(config) != self.KEY_LEN:
            raise PluginErrorBadInput(
                f"xor-rotate-py requires exactly {self.KEY_LEN} bytes "
                f"of config (the XOR key)")
        self._key = bytearray(config)
        self._closed = False

    def max_output_for_input(self, in_len: int) -> int:
        return in_len  # length-preserving

    def forward(self, data: bytes) -> bytes:
        if self._closed:
            from basefwx.plugin import PluginErrorBadState
            raise PluginErrorBadState("plugin already closed")
        out = bytearray(len(data))
        key = self._key
        for i, b in enumerate(data):
            out[i] = b ^ key[i % self.KEY_LEN] ^ ((i * 31) & 0xFF)
        return bytes(out)

    # XOR is self-inverse.
    inverse = forward

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Wipe key material before the bytearray becomes GC'able.
        for i in range(len(self._key)):
            self._key[i] = 0
