# Native ABI policy

BaseFWX has two different native interfaces with different compatibility
contracts.

## Plugin ABI

`cpp/include/basefwx/plugin.h` is the stable, compiler-neutral C plugin ABI.
`BASEFWX_PLUGIN_API_VERSION` gates incompatible changes. Existing fields are
not reordered or removed; the reserved tail is used for compatible growth.
The C++ helpers in `plugin.hpp` and `plugin_static.hpp` wrap that C contract.

## C++ library ABI

`libbasefwx.so.3` exposes the public C++ headers under
`cpp/include/basefwx/`. It is not a compiler-neutral ABI: consumers must use a
compatible C++ standard library and toolchain. CMake package compatibility is
limited to the same BaseFWX minor line, and Debian uses a package-level
`shlibs` floor so binaries using the 3.8 protocol primitives cannot resolve
against an older `libbasefwx.so.3`.

The command-line implementation is not part of this interface. CLI headers
live under `cpp/src/cli/`, are not installed, and GPL CLI objects are linked
only into the `basefwx` executable. The shared library and its installed
headers remain LGPL-3.0-or-later.

Breaking a released C++ ABI requires a deliberate SONAME/package transition.
Additive APIs within the current 3.8 line must preserve existing exported
signatures. Because C++ symbol files are compiler- and standard-library-
sensitive, Debian tracks the minimum runtime as a whole package through
`debian/libbasefwx3.shlibs`; the stable plugin C ABI remains the preferred
interface for independently built binary extensions.
