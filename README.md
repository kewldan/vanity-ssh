# vanity-ssh

[![CI](https://github.com/kewldan/vanity-ssh/actions/workflows/ci.yml/badge.svg)](https://github.com/kewldan/vanity-ssh/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/kewldan/vanity-ssh)](https://github.com/kewldan/vanity-ssh/releases)
![macOS](https://img.shields.io/badge/macOS-13%2B-000000?logo=apple)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Find an Ed25519 SSH key whose fingerprint spells something, using the GPU on your Mac.

```console
$ vanity-ssh kewldan -o ~/.ssh/id_ed25519_kewldan
Looking for "kewldan" (prefix, any case): ~34.4G keys on average.
Building a 120 MB table on the GPU…
Using Apple M4 Pro.
SHA256:KewLdAnP2lTK+DNRYI1e7+oe7Vwabjg9LKKlGL3mf2U

Private key: /Users/you/.ssh/id_ed25519_kewldan
Public key:  /Users/you/.ssh/id_ed25519_kewldan.pub
```

That fingerprint is what `ssh-keygen -l`, GitHub's key settings and `git log --show-signature`
display. It took 48 minutes on an M4 Pro.

- **Fast.** About 5.5 million keys per second on an M4 Pro, 8 times faster than a CPU search on
  all 12 of its cores.
- **Ordinary keys.** The result is a normal OpenSSH `ssh-ed25519` key that `ssh`, `ssh-keygen`,
  `git` and GitHub accept as-is.
- **Checked twice.** Every match the GPU reports is derived again on the CPU with CryptoKit
  before it's written to disk.
- **One binary.** No dependencies at runtime; the Metal kernels are compiled on first use.

## Install

Download the latest release (a universal binary for Apple Silicon and Intel Macs):

```sh
gh release download --repo kewldan/vanity-ssh --pattern '*.tar.gz' --pattern checksums.txt
shasum -a 256 -c checksums.txt
tar -xzf vanity-ssh-*-macos-universal.tar.gz
sudo install vanity-ssh-*-macos-universal/vanity-ssh /usr/local/bin/
```

You can also download the archive from the
[Releases](https://github.com/kewldan/vanity-ssh/releases) page. The binary isn't notarized, so
macOS blocks a copy downloaded with a browser; clear the quarantine flag with `xattr -d com.apple.quarantine /usr/local/bin/vanity-ssh`.

Or build it from source with Xcode 16 or newer:

```sh
git clone https://github.com/kewldan/vanity-ssh
cd vanity-ssh
swift build -c release
sudo install .build/release/vanity-ssh /usr/local/bin/
```

## Usage

```sh
vanity-ssh kewl                                # fingerprint starts with "kewl", any case
vanity-ssh KeWl --case-sensitive               # exactly "KeWl"
vanity-ssh dano --position suffix              # ends with "dano"
vanity-ssh 1337 --position contains            # "1337" anywhere
vanity-ssh kewl -o ~/.ssh/id_ed25519 -C "me@laptop"
vanity-ssh --benchmark                         # measure your GPU
```

The private key is written to `-o` (default `./id_ed25519_vanity`, mode 0600) and the public key
to the same path with `.pub`. Existing files are never overwritten.

The key has no passphrase, like `ssh-keygen -N ""`. To add one afterwards:

```sh
ssh-keygen -p -f ~/.ssh/id_ed25519_kewl
```

### What you can search for

A fingerprint is 43 base64 characters, so a pattern can use `A-Z`, `a-z`, `0-9`, `+` and `/`.
There is no `-`, `_` or `.`.

By default letters match in any case, which halves the work per letter.

The last character of a fingerprint is always one of `AEIMQUYcgkosw048`, so a
`--position suffix` pattern has to end with one of those. In any-case mode either case is enough:
`dano` works because `o` is in the list, `dan` doesn't because neither `n` nor `N` is.

### How long it takes

Each letter multiplies the work by 32 (by 64 with `--case-sensitive`); digits, `+` and `/`
multiply it by 64. Mean times on an M4 Pro at 5.5 million keys/s for a prefix:

| Letters | Any case    | Case-sensitive |
| ------: | ----------- | -------------- |
|       4 | instant     | 3 seconds      |
|       5 | 6 seconds   | 3 minutes      |
|       6 | 3 minutes   | 3.5 hours      |
|       7 | 1.7 hours   | 9 days         |
|       8 | 2.3 days    | 1.6 years      |

These are averages and the search has no memory: you're 63% likely to finish within the mean time
and 95% likely within three times it. `--position contains` accepts the pattern at every position,
so a 4-letter pattern is found about 40 times faster. The progress line shows the mean time for your pattern and GPU.

## Signing git commits with the key

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_kewl.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Lets `git log --show-signature` verify your own signatures locally.
echo "$(git config user.email) namespaces=\"git\" $(cat ~/.ssh/id_ed25519_kewl.pub)" \
  >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

Then add the public key to GitHub as a **signing** key, so that your commits show as Verified:

```sh
gh auth refresh -h github.com -s admin:ssh_signing_key
gh ssh-key add ~/.ssh/id_ed25519_kewl.pub --type signing --title "vanity signing key"
```

## How it works

OpenSSH stores an Ed25519 private key as a 32-byte seed. The public key is derived from it as
RFC 8032 specifies, and the fingerprint is the SHA-256 of the public key blob:

```
seed ──SHA-512──▶ clamp ──× base point──▶ public key ──SHA-256──▶ base64 fingerprint
```

Each GPU thread runs that whole chain for 32 seeds:

- The scalar multiplication uses a fixed-base table of 16 rows × 65,536 precomputed points
  (120 MB, built on the GPU at startup), so a key costs 16 point additions and no doublings.
- The 32 keys share one field inversion (Montgomery's trick).
- Field arithmetic uses ten 25.5-bit limbs, so every product is a 32×32→64-bit multiply.
- The fingerprint is compared against the pattern as 6-bit base64 values, so nothing is
  base64-encoded on the GPU.

A shortcut that steps through consecutive scalars would be far faster, but it can't produce a
seed, and without a seed the key can't be stored in OpenSSH's format. vanity-ssh only creates
keys that OpenSSH itself could have generated.

## Security

- Each batch of about 4 million seeds starts from 32 fresh bytes from the system CSPRNG
  (`SecRandomCopyBytes`); seed *i* of a batch is that value with *i* XORed into its first four
  bytes. The found key is as unpredictable as one from `ssh-keygen`.
- The seed never leaves your machine and is never printed. Only the key files contain it.
- The GPU code is tested against CryptoKit on thousands of random keys, and each match is
  re-derived with CryptoKit before it's saved.

A vanity fingerprint is for fun and recognisability, not security: anyone can find a key whose
fingerprint starts with the same few characters, so check the whole fingerprint when it matters.

## Development

```sh
make test     # unit tests; the GPU tests compare against CryptoKit
make lint     # swift-format, clang-format and the embedded-kernel check
make format   # apply formatting and regenerate the embedded kernel
make build    # release build
```

The Metal source lives in `Sources/VanitySSH/Metal/Kernel.metal`. After editing it, run
`scripts/embed-kernel.sh` (or `make format`) to regenerate `KernelSource.swift`, which embeds it
in the binary.

Releases are built by GitHub Actions when a `v*` tag is pushed. The tag has to match the version
in `Sources/VanitySSH/Version.swift`.

## License

[MIT](LICENSE)
