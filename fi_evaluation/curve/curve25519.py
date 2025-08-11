from typing import Iterable

from cryptography.hazmat.primitives.asymmetric import x25519
from fi_evaluation.curve import Curve


class Curve25519(Curve):
    # One of the special points from https://cr.yp.to/ecdh.html
    _small_subgroup_point_int = 325606250916557431795983626356110631294008115727848805560023387167927233504

    def __init__(self):
        super().__init__("Curve25519")

    @staticmethod
    def small_subgroup_point() -> bytes:
        return Curve25519._small_subgroup_point_int.to_bytes(32, 'little')

    def shared_secret(self, public_key_bytes: bytes, private_key_bytes: bytes) -> bytes:
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        shared_secret_bytes = private_key.exchange(public_key)
        return shared_secret_bytes

    def clamp(self, key: bytes) -> bytes:
        key_int = int.from_bytes(key, byteorder='little')
        key_int &= ~(1 << 255)  # highest bit is 0
        key_int |= (1 << 254)  # second highest bit is 1
        key_int &= ~7  # lowest three bits are 0
        return key_int.to_bytes(32, 'little')

    def preprocess_key(self, key: bytes) -> bytes:
        return self.clamp(key)

    def generate_known_outputs(self) -> Iterable[tuple[bytes, int]]:
        # Result representing the neutral element - probably generated
        # by providing a point in the order-8 subgroup.
        yield (0).to_bytes(32, 'little'), 0
