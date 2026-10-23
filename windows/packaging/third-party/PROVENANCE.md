# Third-party components bundled with the Windows edition

## wireguard.dll — WireGuardNT (bundled, unmodified)

- **What it is:** WireGuardNT, the official WireGuard
  implementation for the NT kernel, deployed as the
  platform-specific `wireguard.dll` that applications install
  side-by-side with themselves (its own README's model).
- **Source:** the official wireguard-nt binary distribution,
  `wireguard-nt-1.0.zip`, from `download.wireguard.com`
  (`https://download.wireguard.com/wireguard-nt/wireguard-nt-1.0.zip`).
  - Distribution zip SHA-256:
    `d44f53300e47b44c53e77ee4c495cf061d06b5739f28872432ee1596107a302d`
  - This file is the distribution's `bin/amd64/wireguard.dll`,
    byte-for-byte: SHA-256
    `40add3d0b47bee347fcad0f59a0a68ca3d98fb4f7aa90cc4e8ff76086219eca7`
- **Unmodified.** It is never patched, repacked, or renamed —
  the license requires the precise downloaded contents, and the
  test suite pins the SHA-256 above so a swapped binary fails
  the build.
- **License:** WireGuard LLC's *Prebuilt Binaries License*,
  shipped verbatim beside it as `WireGuardNT-LICENSE.txt` (the
  `LICENSE.txt` from inside the same distribution zip). In
  short: the DLL's *source* project lives under other terms,
  but the prebuilt binary may be redistributed alongside other
  software that uses it only via the Permitted API (the
  `wireguard.h` interfaces) — which is exactly how Sphinx uses
  it, loaded at runtime and driven through those interfaces.
  The DLL is **not** MIT-licensed, and Sphinx never represents
  it as such; Sphinx's own code remains MIT.
- **Not bundled: wintun.dll.** WireGuardNT is a kernel
  implementation and does not use Wintun (Wintun serves
  userspace tunnel implementations). Shipping an unused DLL
  would misstate what runs, so it is not here. Wintun's prebuilt
  binary terms were evaluated alongside WireGuardNT's (same
  Prebuilt Binaries License model, from wintun.net's
  distribution) and are recorded in windows/README.md.
