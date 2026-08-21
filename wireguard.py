"""WireGuard helpers: X25519 key generation, client config and QR codes."""

import base64
import io
import os

_P = 2**255 - 19
_A24 = 121665
_BASE = 9


def _clamp(k: bytes) -> bytes:
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def _x25519(k: bytes, u: int) -> bytes:
    """Curve25519 scalar multiplication (RFC 7748 ladder). Caller must clamp k."""
    x1 = u % _P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(255, -1, -1):
        kt = (k[t // 8] >> (t % 8)) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt

        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = ((da + cb) * (da + cb)) % _P
        z3 = (x1 * ((da - cb) * (da - cb))) % _P
        x2 = (aa * bb) % _P
        z2 = (e * (aa + _A24 * e)) % _P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_b64, public_key_b64) for a WireGuard peer."""
    private = _clamp(os.urandom(32))
    public = _x25519(private, _BASE)
    return _b64(private), _b64(public)


def derive_public_key(private_key_b64: str) -> str:
    """Derive public key from a base64-encoded private key."""
    raw = base64.b64decode(private_key_b64)
    clamped = _clamp(raw)
    public = _x25519(clamped, _BASE)
    return _b64(public)


def build_client_config(
    client_private_key: str,
    client_address: str,
    server_public_key: str,
    server_endpoint: str,
    dns: str,
    allowed_ips: str = "0.0.0.0/0",
    persistent_keepalive: int = 0,
) -> str:
    """Build a standard WireGuard client .conf text."""
    lines = [
        "[Interface]",
        f"PrivateKey = {client_private_key}",
        f"Address = {client_address}",
    ]
    if dns:
        lines.append(f"DNS = {dns}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"AllowedIPs = {allowed_ips}",
        f"Endpoint = {server_endpoint}",
    ]
    if persistent_keepalive:
        lines.append(f"PersistentKeepalive = {persistent_keepalive}")
    return "\n".join(lines)


def build_qr_png(config_text: str, box_size: int = 8) -> bytes:
    """Render config text as a PNG QR code."""
    import qrcode
    from qrcode.constants import ERROR_CORRECT_M

    qr = qrcode.QRCode(error_correction=ERROR_CORRECT_M, box_size=box_size, border=2)
    qr.add_data(config_text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
