# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

"""Compatibility coverage for retired text codecs and hashes."""

import unittest

from basefwx.features import RETIRED_MEDIA_ENABLED
from basefwx.main import basefwx


@unittest.skipUnless(
    RETIRED_MEDIA_ENABLED,
    "retired compatibility is disabled",
)
class RetiredCodecCompatibilityTests(unittest.TestCase):
    B256 = "4PK6OP9A65TJISRC9CQM2UP85944EG984PF4CAI7AOK2KI3JDDBG4"
    A512 = (
        "22659442R15AKJ4EAI3593KGGI159442R15AKJ4EAI35154GAI7BSKKKI2JFLR7QTH"
        "8593KCH2V5554GKRTEOK4GK216TUNCNP999456A28A10JEL968SL46L968SL46A2A90"
        "L4EIAL50J5CL968SL46NP999456A2A90L4EAI791142IAL50J5CIAL50J5C3"
    )

    def test_reversible_codecs_round_trip(self) -> None:
        self.assertEqual(basefwx.b256encode("basefwx"), self.B256)
        self.assertEqual(basefwx.b256decode(self.B256), "basefwx")
        self.assertEqual(basefwx.a512encode("basefwx"), self.A512)
        self.assertEqual(basefwx.a512decode(self.A512), "basefwx")

    def test_retired_hash_shapes_remain_stable(self) -> None:
        self.assertEqual(
            basefwx.bi512encode("basefwx"),
            "47d28c46896d43b415dde8a79eed97da6ac6686127f595fa28bce0a0492df42d",
        )
        self.assertEqual(
            basefwx.uhash513("basefwx"),
            "a2a622418b25e4ec8c9a08f61b979fe8bb17272d34983bbbed44740fffd3c4b4",
        )


if __name__ == "__main__":
    unittest.main()
