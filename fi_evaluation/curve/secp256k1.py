from cryptography.hazmat.primitives.asymmetric import ec
from fi_evaluation.curve import Curve


class SECP256K1(Curve):
    name = "secp256k1"
    _base_point = bytes.fromhex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

    def base_point(self) -> bytes:
        return SECP256K1._base_point

    def shared_secret(self, public_key_bytes: bytes, private_key_bytes: bytes) -> bytes:
        try:
            private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, 'big'), ec.SECP256K1())
        except ValueError as exc:
            raise ValueError(f"Invalid private key for secp256k1 curve {private_key_bytes.hex()}.") from exc

        if len(public_key_bytes) == 64:
            # The library expects the "uncompressed key" prefix (0x04)
            public_key_bytes = b'\x04' + public_key_bytes

        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)
        shared_secret_bytes = private_key.exchange(ec.ECDH(), public_key)
        return shared_secret_bytes
