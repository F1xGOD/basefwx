<!-- Generated from docs/src/en_US/man/basefwx_1.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# basefwx

command-line cryptographic codec tool

## SYNOPSIS

```text
basefwx [global flags] <command> [args]

basefwx fwxaes-enc <file> [--password <password>] [--out <path>]
basefwx fwxaes-dec <file> [--password <password>] [--out <path>]
basefwx fwxaes-live-enc <file|-> [--password <password>] [--out <path|->]
basefwx fwxaes-live-dec <file|-> [--password <password>] [--out <path|->]
basefwx identify <file>
basefwx completion bash
```

## DESCRIPTION

basefwx is the command-line frontend for the BaseFWX cryptographic codec
library. It encrypts files, decodes BaseFWX containers, inspects container
metadata, runs reversible text and binary encodings, and processes packetized
live streams.

The retired media carrier commands are not part of a default build. See
**RETIRED MEDIA COMMANDS**
below.

The CLI is packaged separately from the shared library. Installing the
basefwx package pulls in libbasefwx4 automatically; applications that only
need the library can depend on libbasefwx4 or libbasefwx-dev without
installing the CLI.

## GLOBAL FLAGS

- **--verbose, -v**

  Show additional routing and build information where a command supports it.

- **--no-log**

  Suppress non-essential log output.

- **--no-color**

  Disable styled terminal output.

- **--version, -V**

  Print version and feature information.

## GENERAL COMMANDS

- **help**

  Print command usage.

- **version**

  Print build version and enabled feature flags.

- **completion bash**

  Print a bash completion script.

- **info** *file.fwx*

  Print BaseFWX container information.

- **identify** *file*

  Print a formatted container summary.

- **probe** *file*

  Alias for identify.

## FILE ENCRYPTION

- **fwxaes-enc** *file* [--password *password*] [--out *path*]

  Encrypt a file with the fwxAES container path.

- **fwxaes-dec** *file* [--password *password*] [--out *path*]

  Decrypt a fwxAES container after authentication succeeds.

- **fwxaes-heavy-enc, fwxaes-heavy-dec**

  Aliases for the heavy fwxAES mode.

- **fwxaes-stream-enc, fwxaes-stream-dec**

  Stream-oriented fwxAES file modes.

- **fwxaes-live-enc, fwxaes-live-dec**

  Packetized live stream encryption and decryption. Use "-" for stdin or
  stdout where supported.

- **an7** *file.fwx* [--password *password*] [--out *path*] [--keep-input] [--force-any]

  Apply the reversible AN7 stealth transform to a file that is already
  encrypted. Unlike the commands above, an7 never reads the password as a
  positional argument. It takes the input path, then only the flags listed
  here, and the password arrives through **--password** or **-p**. Keys come
  from Argon2id over a fresh 16-byte salt at time cost 5, 128 MiB, and
  parallelism 4. The payload is rewritten in 1 MiB chunks, then an encrypted
  trailer and a 64-byte footer are appended. The input must end in .fwx unless
  **--force-any** is given. Without **--out** the result is written beside the
  input as "data" followed by ten random digits, and an **--out** path that
  names an existing directory receives that generated name. The input file is
  removed on success unless **--keep-input** is given.

- **dean7** *file* [--password *password*] [--out *path*] [--keep-input]

  Reverse an AN7 file and print the restored path. The original name,
  extension, and SHA-256 digest are read from the encrypted trailer, and the
  digest is checked before the command reports success. The password is
  supplied the same way as for an7, and **--force-any** is rejected here.
  Without **--out** the restored file is written beside the input under its
  recovered original name. The input file is removed on success unless
  **--keep-input** is given.

- **b512file-enc, b512file-dec, pb512file-enc, pb512file-dec**

  Password-backed file codec modes.

## TEXT AND BINARY CODECS

- **b64-enc, b64-dec**

  Base64 text encode/decode helpers.

- **n10-enc, n10-dec, n10file-enc, n10file-dec**

  BaseFWX n10 text and file encoders.

- **hash512**

  SHA-512 hash helper command.

- **b512-enc, b512-dec, pb512-enc, pb512-dec**

  Password-backed text codec modes.

## BENCHMARK COMMANDS

The bench commands are measurement helpers, not data-processing commands. Each
one prints
**BENCH_NS=***n*
with the median wall-clock nanoseconds of one timed iteration. Some commands
also print a verification or throughput line. All leave the named input in
place, but only bench-an7, bench-dean7, bench-b512file, and bench-pb512file copy
or seed per-worker inputs in owner-only temporary directories. The fwxAES commands read
the named input into memory, and bench-live reads it directly.

Iteration and thread counts come from the environment:
**BASEFWX_BENCH_WARMUP**
(default 2),
**BASEFWX_BENCH_ITERS**
(default 50),
**BASEFWX_BENCH_WORKERS**
(default the detected hardware concurrency), and
**BASEFWX_BENCH_PARALLEL**
set to 0, false, off, or no to force a single worker. Every bench command
except bench-hash also accepts the master-key flags described in
**KEY OPTIONS**
below.

- **bench-text** *method* *text-file* [--password *password*]

  Time one encode plus decode round trip of the file's text. *method* is b64,
  n10, b512, or pb512. The b512 and pb512 methods take a password and also
  accept --kdf and --pbkdf2-iters.

- **bench-hash** *method* *text-file*

  Time hashing of the file's text. *method* is hash512. This command takes no
  flags.

- **bench-fwxaes** *file* *password*

  Time one in-memory fwxAES encrypt plus decrypt round trip over the file
  bytes. This one is single-threaded and ignores the worker setting.

- **bench-fwxaes-par** *file* *password*

  Time the same fwxAES round trip spread across worker threads. It prints an
  extra **THROUGHPUT_GiBps=***value* WORKERS=*n* line when the measurement is
  usable.

- **bench-an7** *file* *password*

  Time an7 over a per-worker fwxAES-encrypted seed built from the input.

- **bench-dean7** *file* *password*

  Time dean7 over a per-worker AN7 seed built the same way.

- **bench-live** *file* *password*

  Time a packetized live encrypt plus decrypt round trip in memory and verify
  the restored length. In the C++ CLI the worker count is capped to fit the
  input size and available memory, and a warning names the reduced count.
  **BASEFWX_BENCH_MEMORY_LIMIT_BYTES** overrides that C++ memory budget. The
  Java command uses the configured worker count without this extra cap and
  prints **BENCH_VERIFIED_BYTES=***n*.

- **bench-b512file** *file* *password*

  Time a b512 file encode plus decode round trip on a per-worker copy of the
  input.

- **bench-pb512file** *file* *password*

  Time the same round trip through the pb512 file codec.

Both C++ and Java bench-fwxaes-par print
**THROUGHPUT_GiBps=***value* WORKERS=*n*
when the measurement is usable. Java bench-live also prints the verified-byte
line described above.

## RETIRED COMPATIBILITY COMMANDS

b256, A512, Bi512, Uhash513, the jMG media cipher, and the kFM/kFA carrier
codecs are retired. A default build does not compile or install them, and the
commands below are absent from its help output and completion script.

They exist only in a compatibility build, configured with
**-DBASEFWX_ENABLE_RETIRED_MEDIA=ON**,
and is meant for reading retired data that already exists. That build preserves
the historical commands, formats, and bytes; it receives security, correctness,
and existing-data compatibility fixes only. Encrypt new media with
**fwxaes-enc**
instead.

Because the switch selects what gets compiled, it cannot restore these commands
in an artifact that was built without them. Use a compatibility build of the
same BaseFWX version that wrote the file.

- **b256-enc, b256-dec, a512-enc, a512-dec, bi512-enc, uhash513**

  Historical text codecs retained for exact-byte and decode compatibility.

- **jmge** *media* [--password *password*] [--out *path*]

  Encode media through the jMG media cipher path.

- **jmgd** *media* [--password *password*] [--out *path*]

  Decode jMG media output.

- **kFMe** *input* [--out *path*] [--bw]

  Encode into a strict BaseFWX carrier format.

- **kFMd** *input* [--out *path*] [--bw]

  Decode a strict BaseFWX carrier. Plain media that is not a BaseFWX carrier
  is rejected.

- **kFAe, kFAd**

  Deprecated aliases for the PNG-only carrier path.

## KEY OPTIONS

- **--password** *password*

  Provide a password on the command line. Passworded commands prompt on a TTY
  when this option is omitted.

- **--use-master, --no-master**

  Enable or disable master-key wrapping where a command supports it. Provision
  the intended public key, retain metadata, and verify complete-file recovery
  independently. Some file paths replace requested master intent with key
  availability or metadata stripping, so command success does not establish
  that a recoverable master wrap was written. Streaming B512 uses STRMOBF1 and
  still requires the original password for its internal obfuscation. The
  reader does not authenticate that password separately; a matching master key
  with a wrong password can produce corrupted output. For password recovery
  with an unrelated configured master private key, use **--no-master**.
  Enabled master recovery is tried first; payload authentication failure does
  not retry the password path.

- **--master-pub** *path*

  Use a master public key file where supported.

- **--master-autogen**

  Deprecated and has no effect since 3.7.0. It only implies **--use-master**.
  Silent EC master autogeneration was removed.

- **--allow-embedded-master**

  Allow embedded master-key metadata where supported.

- **--strip-meta**

  Omit file-container metadata where supported. AES-heavy pb512file authoring
  rejects this option because its KDF costs require metadata for recovery.
  B512file authoring also rejects it when the input selects the streaming
  container, whose metadata carries the required dispatch marker.

- **--kdf** *label*, --pbkdf2-iters *n*

  Select key-derivation behavior where a command supports it.

## DATA FLOW

<!-- yume-diagram: data_flow -->
```text
+-----------------------------+
|  INPUT                      |
|  file, stream, or text      |
+--------------+--------------+
                \
                 \
                  v
   +--------------+--------------+
   |  BASEFWX CLI                |
   |  selected command + options |
   +--------------+--------------+
                   \
                    \
                     v
      +--------------+--------------+
      |  BASEFWX OUTPUT             |
      |  container or stream        |
      +-----------------------------+
```
<!-- /yume-diagram -->

## EXIT STATUS

The command exits with status 0 on success and non-zero on invalid usage,
decode failure, authentication failure, I/O failure, or missing build support
for a requested feature.

## SEE ALSO

**basefwx**(7)

YUME is a separate sibling project that can link against
**libbasefwx**;
its manual pages (if installed) are
**yume**(1)
and
**yumed**(8).
Those binaries and man pages are
**not**
part of this BaseFWX source tree.
