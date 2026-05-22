# BaseFWX licensing — the practical version

> The legal text lives in [`LICENCE`](./LICENCE). This file explains
> what that text means in everyday cases. If anything below
> disagrees with `LICENCE`, `LICENCE` wins.

## In one paragraph

BaseFWX is **dual-licensed**. Most users get it for free under
**GPL-3.0 plus two additional terms** — a *Plugin Exception* that lets
you ship closed-source `.so` / `.dll` / `.jar` plugins, and an
*Attribution requirement* that you credit BaseFWX prominently in your
product. Companies that need different terms (no attribution,
proprietary linking, etc.) can purchase a separate **commercial
license** from FixCraft Inc. (`admin@fixcraft.jp`). Open users do not
need to contact anyone; just follow `LICENCE` and you're done.

## The matrix

| What you do | License you operate under | Allowed? |
| --- | --- | --- |
| Read / study BaseFWX source code | GPL-3.0 | Yes. |
| Use unmodified BaseFWX in your own product, credit it visibly | GPL-3.0 + Attribution | Yes — see [Attribution rules](#attribution-rules) below. |
| Use unmodified BaseFWX in your own product, *without* visible attribution | requires Commercial License | Contact `admin@fixcraft.jp`. |
| Modify BaseFWX, ship the modified version under GPL-3.0 | GPL-3.0 + Attribution | Yes. Source must be made available. |
| Modify BaseFWX, ship the modified version under proprietary / closed-source terms | requires Commercial License | Contact `admin@fixcraft.jp`. (The free GPL-3.0 track doesn't allow this; see "No closed-source forks" below.) |
| Write a plugin against the public ABI/SPI, ship it closed-source | Plugin Exception | Yes — any license you choose, including proprietary. See [Plugin Exception rules](#plugin-exception-rules). |
| Write a plugin and statically link BaseFWX object files | GPL-3.0 + Attribution | The plugin counts as a derivative work. Use dynamic loading instead, or buy a commercial license. |
| Use a file from `examples/plugins/` as a **starting template** for your own plugin | **You choose** (Plugin-Template Exception, LICENCE clause 5) | Ship the derived plugin under any license, including closed-source, provided it still qualifies as a Plugin under the Plugin Exception (clause 1). Attribution requirement still applies to the end product that loads BaseFWX. |
| Copy-paste BaseFWX source files from *outside* `examples/plugins/` into your codebase | GPL-3.0 + Attribution applies to the whole codebase | You're now shipping BaseFWX. License accordingly or buy a commercial license. |

## Attribution rules — what counts as "prominent"

The free GPL-3.0 track requires the credit string

> **Powered by BaseFWX — https://github.com/F1xGOD/basefwx**

to appear in a place where it's actually seen by users of your
product. The bar isn't subjective:

- **Where the credit goes:** on the same screen / page / dialog /
  surface that already carries your product's other third-party
  attributions — the **credits / about / acknowledgments / open-source
  notices** surface. If your product has an "About" screen, a
  "Credits" screen, a settings → "Open-source components" page, or a
  CLI `--version` flag that lists dependencies, the BaseFWX credit
  belongs **right there, alongside the others**. If your product has
  none of these surfaces, you need to add one for this attribution.
- **Where the credit does NOT have to go:** the credit does **not**
  belong on the main / home / landing screen of your app. Mixing
  third-party attribution into your primary UX is awkward for users
  and not what this license is asking for. The rule is "with the
  other credits", not "front and center".
- **How big:** in a font / weight / size equal to or larger than the
  smallest credit already on that surface. "Smallest" is measured
  by visual rendering, not source-code length.
- **What's included:** the full string above, including the project
  URL. "BaseFWX" alone is not enough.

What does **NOT** satisfy attribution:

- Buried 3 menus deep when other open-source credits sit on a
  single, easily-discovered credits page (i.e. listed in a less
  prominent location than peer credits).
- "BaseFWX" abbreviated, without the URL.
- A footnote in 6pt grey on a white background when other credits
  are 12pt black.
- Mentioned in a `LICENSE.txt` file in the repo but not surfaced to
  end users of the binary product.

If you're not sure whether your attribution placement passes the
bar, open an issue with a screenshot. The maintainers will tell you
yes or no. The point is to be clear, not adversarial.

### "Hidden BaseFWX" — paid attribution removal

If the credit line above does not fit your product — white-label
deployments, branding policy forbidding third-party callouts,
contractual obligations to other licensors, or simply a preference
to not name dependencies publicly — the **commercial license**
includes an **attribution-removal option**. Contact
`admin@fixcraft.jp` with a short note describing your product and
the reason for hiding the credit; pricing is per-customer. With the
commercial license active, the GPL-3.0 + Attribution requirement no
longer applies to your usage and the "Powered by BaseFWX" string is
not required anywhere in your product.

This is intentionally a paid tier, not a free toggle. The
attribution is the consideration for the GPL-3.0 free track;
removing it shifts you to commercial terms. See the [Commercial
license](#commercial-license) section below for the broader scope of
what the commercial license unlocks.

## Plugin Exception rules — when is your plugin in the safe harbor?

Your plugin is NOT considered a derivative work of BaseFWX, and you
can license it under any terms you want (including closed-source),
if **all four** of these hold:

1. **Separate artifact.** Your plugin is shipped as a separate file
   — a shared library (`.so`/`.dll`/`.dylib`) or a Java archive
   (`.jar`) — not statically built into the BaseFWX binary.
2. **Loaded through documented entry points.** BaseFWX loads your
   plugin via one of:
   - C/C++: `dlopen` of the `.so` plus `dlsym basefwx_plugin_entry`
   - Java: `java.util.ServiceLoader` of
     `com.fixcraft.basefwx.plugin.BasefwxPluginFactory`
   - Python: `basefwx.plugin.register` / `register_native` /
     entry-point group `basefwx.plugins`
3. **Headers only.** Your plugin source only `#include`s or
   `import`s the public ABI/SPI headers:
   - `basefwx/plugin.h`
   - `basefwx/plugin.hpp`
   - the Java package `com.fixcraft.basefwx.plugin`
   - the Python module `basefwx.plugin`
4. **Dynamically linked.** Your plugin is dynamically linked, not
   statically linked, to any BaseFWX code.

The two example plugins in `examples/plugins/` (`xor-rotate` for C++
and `xor-rotate-java` for Java) satisfy all four. If yours does too,
you're done — pick whatever license you want for your plugin code.

## Plugin-Template Exception (LICENCE clause 5)

The source files in `examples/plugins/` are GPL-3.0 like the rest of
the project, **with one additional permission**: you may use them as
starting templates for your own plugin under any license you choose,
provided the derived plugin still satisfies the four Plugin Exception
conditions above (separate `.so` / `.dll` / `.dylib` / `.jar`,
dynamic-linked, no other BaseFWX source embedded, loaded via the
documented entry points).

In other words:

- **Read, fork, copy, gut, edit** the files in `examples/plugins/`.
- **License your derived plugin however you want** — closed-source
  commercial, MIT, Apache-2.0, anything.
- **You do not need to GPL your plugin** just because you started from
  a GPL-licensed example.
- **Attribution still applies** to the *end product that loads
  BaseFWX*. Your plugin isn't BaseFWX, but the host application that
  links BaseFWX is, and that host must credit BaseFWX in its user-visible
  surface (see Attribution rules above).

This exception applies ONLY to files under `examples/plugins/`.
Modifying or copying any other BaseFWX source file remains subject to
GPL-3.0 copyleft.

The header at the top of each example file states the same in short
form. If you see a file under `examples/plugins/` without that
header, treat it as a bug and report it.

## What you CAN do (free track)

- Write and distribute a closed-source `.so` / `.dll` / `.dylib` /
  `.jar` plugin under any license you choose, including commercial
  terms.
- Sell a plugin as a paid product (your plugin is yours to license).
- Ship unmodified BaseFWX inside your closed-source product, with
  visible attribution.
- Maintain a private fork of BaseFWX for internal use, as long as
  you don't redistribute the modified version externally.
- Use BaseFWX in academic research, in non-commercial open-source
  projects, in personal projects — anywhere GPL-3.0 is acceptable.

## What you CANNOT do (free track)

- Distribute a modified BaseFWX closed-source. The Plugin Exception
  does not cover modifications to the core. → buy commercial license
  or keep your modifications private.
- Use BaseFWX without visible attribution. → buy commercial license.
- Embed BaseFWX source files inside your plugin to avoid the ABI
  boundary. The exception requires the plugin to be a separate,
  dynamically-loaded artifact.
- Statically link BaseFWX into your application without GPL'ing the
  whole application. → use dynamic linking, write a plugin, or buy
  commercial license.

## Static-embedded plugins (commercial track)

3.7.0 ships [`basefwx/plugin_static.hpp`](./cpp/include/basefwx/plugin_static.hpp),
an in-process plugin registry. Calling
`basefwx::plugin::Registry::Register(...)` lets the host resolve a
plugin by its 16-byte ID without `dlopen`, so the plugin source can
be compiled directly into the host binary with no `.so` on disk.
The [`examples/plugins/static-embed/`](./examples/plugins/static-embed/)
example demonstrates the pattern end-to-end.

How this interacts with the dual-license:

- **Static plugin against a dynamically-linked BaseFWX** stays inside
  the free track (GPL-3.0 + Attribution). The plugin source you embed
  is yours; the host just loads BaseFWX as a shared library.

- **Static plugin against a statically-linked BaseFWX** — i.e. a
  single-file binary with both BaseFWX and the plugin baked in —
  needs a **commercial license**, same as any other static linking
  of BaseFWX. The licensing question is about how BaseFWX is linked,
  not how plugins are registered.

For the security implications of static embedding, read
[examples/plugins/THREAT_MODEL.md](./examples/plugins/THREAT_MODEL.md).
The short version: static embedding raises the cost of extracting
the plugin code from the binary, but extraction cost is not
cryptographic security. The actual security mechanism is making the
plugin **keyed** via `forward_keyed` / `inverse_keyed`, so that
extracting the plugin and its config still doesn't let an attacker
reproduce the transform without the user's password / host-derived
secret. Static embedding alone is not a substitute for keyed
plugins.

## Commercial license

Available on request. Typical reasons companies buy:

- **"Hidden BaseFWX"** — remove the "Powered by BaseFWX" attribution
  entirely (white-label, branding policy, contractual constraints).
  See the [Hidden BaseFWX](#hidden-basefwx--paid-attribution-removal)
  section above.
- Need to statically link BaseFWX into a single-file distribution
  (the static-embed plugin track above).
- Need to embed BaseFWX in a closed-source SDK that is itself
  redistributed.
- Need indemnification, written warranty, or support SLAs.
- Need to deviate from GPL-3.0 copyleft for derivative works.

Terms and pricing are negotiated per customer. Contact
`admin@fixcraft.jp` — short note explaining your intended use is
sufficient to start.

The commercial license is a separate written agreement; it
does not change the GPL-3.0 + Additional Terms available to other
users.

## Why GPL-3.0 and not AGPL-3.0

BaseFWX is a library that gets embedded in many different consumers.
The "SaaS loophole" that AGPL closes mostly matters for whole hosted
applications, not for a library. AGPL would significantly hurt
adoption (many large companies ban it outright) without protecting
anything the Plugin Exception + commercial license dual-track
doesn't already cover. Projects built on top of BaseFWX (like YUME
server endpoints) can choose AGPL at their own level if they want
network-use copyleft.

## Contributions

External contributors must sign a one-page Contributor License
Agreement (CLA) before their pull requests are merged. The CLA
grants FixCraft Inc. the right to redistribute the contribution
under both the free GPL-3.0 + Additional Terms and any future
commercial license. Without it, the dual-license model breaks the
moment a third party contributes copyrighted code.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the contribution
process and the CLA text.

## Trademarks

"BaseFWX" and "FixCraft" are trademarks of FixCraft Inc. The
GPL-3.0 license grants no trademark rights. You may use the names
in attribution credits (as required above) and to factually
describe interop with the project (e.g. "compatible with BaseFWX").
You may not name your own product "BaseFWX-X" or
"BaseFWX-by-Company" without written permission.

## If you're unsure

Open an issue, or email `admin@fixcraft.jp`. Better to ask before
you ship than discover the answer after a customer audits you.
