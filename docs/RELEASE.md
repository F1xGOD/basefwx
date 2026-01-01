---
layout: doc
title: Release
---

# Release & Signing

This project attaches native CLI binaries to GitHub releases and signs them with GPG.

## Create a GPG key

Interactive:

```
gpg --full-generate-key
```

Quick (ed25519, 1 year):

```
gpg --quick-generate-key "BASEFWX Release <you@example.com>" ed25519 cert 1y
```

List keys and copy the key ID:

```
gpg --list-secret-keys --keyid-format=long
```

Export keys:

```
gpg --armor --export <KEY_ID> > basefwx-release.pub
gpg --armor --export-secret-keys <KEY_ID> > basefwx-release.sec
```

## Configure GitHub Secrets

Add these secrets in your repo settings:

- `GPG_PRIVATE_KEY`: contents of `basefwx-release.sec`
- `GPG_PASSPHRASE`: passphrase used when creating the key

Keep the public key in a safe place or publish it (for verification).

## Verify Signatures

Example:

```
gpg --import basefwx-release.pub
gpg --verify basefwx-linux.sig basefwx-linux
```

## Hash Verification

```
sha256sum -c basefwx-linux.sha256
md5sum -c basefwx-linux.md5
```

On macOS:

```
shasum -a 256 -c basefwx-mac.sha256
md5 -r basefwx-mac | awk '{print $1}'
```
