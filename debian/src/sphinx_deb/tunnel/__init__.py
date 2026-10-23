"""The tunnel layer: everything that touches the machine on the
VPN's behalf — running ``wg`` / ``wg-quick``, resolving endpoint
names, probing the tunnel — behind the guard in ``guard.py``.
The brain (parsing, validation, storage) stays in ``core/``,
platform-free, exactly as the resolver layer relates to the
filter brain."""
