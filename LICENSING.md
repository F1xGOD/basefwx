# BaseFWX licensing

This document is the practical guide.
[`LICENCE`](./LICENCE) is the repository-level license notice.

## Policy

BaseFWX uses a file-level split license:

| Area | License |
| --- | --- |
| Core library, public API, runtime code, JNI/runtime bridges | LGPL-3.0-or-later |
| Plugin ABI/SPI headers and interfaces | LGPL-3.0-or-later |
| Standalone CLIs, tools, benchmarks, release scripts, test orchestrators | GPL-3.0-or-later |
| Example plugins and plugin templates under `examples/plugins/` | MIT OR Apache-2.0 |

The license header at the top of each source file is the source of truth for
that file.
If a file has no header, treat it as a bug and fix the header before
redistribution.

## Library Users

Applications may use the BaseFWX core library under LGPL-3.0-or-later.
That includes the C/C++ headers in `cpp/include/basefwx/`, Java runtime/API
classes under `java/src/main/java/com/fixcraft/basefwx/`, and Python runtime/API
modules under `python/basefwx/`.

Follow the normal LGPL requirements when distributing binaries that link or
bundle BaseFWX, including preserving notices and allowing users to replace or
relink the LGPL-covered library where the LGPL requires it.

## Standalone Tools

The command-line applications, benchmark drivers, release helpers, smoke-test
scripts, and other standalone tools are GPL-3.0-or-later.
Using those tools does not change the license of files they process, but
copying or redistributing tool source follows GPL-3.0-or-later.

## Plugin ABI/SPI

The plugin ABI/SPI is intentionally LGPL-3.0-or-later:

- `cpp/include/basefwx/plugin.h`
- `cpp/include/basefwx/plugin.hpp`
- `cpp/include/basefwx/plugin_static.hpp`
- Java interfaces under `com.fixcraft.basefwx.plugin`
- `python/basefwx/plugin.py`

Plugins that use only those public ABI/SPI surfaces may choose their own
license.
They do not need a special exception to use the ABI.
If a plugin copies BaseFWX implementation files outside the ABI/SPI surface, the
copied files keep their original license.

## Example Plugins

Files under `examples/plugins/` are intentionally permissive templates licensed
as `MIT OR Apache-2.0`.
You may copy, modify, and ship derived plugins under any license compatible with
your project.
Keep the copyright and SPDX notice when copying template files.

## Static Embedding

Static embedding a plugin into a host is a deployment choice.
It does not change the plugin template license.
Static linking or embedding BaseFWX itself follows the LGPL-3.0-or-later
requirements for the BaseFWX library files involved.

## Contributions

External contributors must sign the CLA described in
[`CONTRIBUTING.md`](./CONTRIBUTING.md) before non-trivial changes are merged.
The CLA lets FixCraft Inc. redistribute contributions under the same split
license policy used by the repository.

## Trademarks

"BaseFWX" and "FixCraft" are trademarks of FixCraft Inc.
The open-source licenses grant no trademark rights beyond factual attribution and
compatibility statements.
