from typing import Iterable

from cryptography.hazmat.primitives.asymmetric import x25519
from fi_evaluation.curve import Curve


class Curve25519(Curve):
    name = "curve25519"
    _base_point = bytes.fromhex("09000000000000000000000000000000000000000000000000000000")
    # The special points from https://cr.yp.to/ecdh.html
    _small_subgroup_ints = [
        # The real x coordinates of the 5 small subgroup points.
        0,
        1,
        325606250916557431795983626356110631294008115727848805560023387167927233504,
        39382357235489614581723060781553021112529911719440698176882885853963445705823,
        2 ** 255 - 19 - 1,

        # The x coordinates increased by the prime P. These, when reduced mod P, produce the 5 points above.
        2 ** 255 - 19 + 0,
        2 ** 255 - 19 + 1,
        2 ** 255 - 19 + 325606250916557431795983626356110631294008115727848805560023387167927233504,
        2 ** 255 - 19 + 39382357235489614581723060781553021112529911719440698176882885853963445705823,
        2 ** 255 - 19 + 2 ** 255 - 19 - 1,  # = 2 * (2 ** 255 - 19) - 1

        # The x coordinates increased by twice the prime P. Only 0 and 1 will fit into 255 bits.
        2 * (2 ** 255 - 19) + 0,
        2 * (2 ** 255 - 19) + 1
    ]

    def base_point(self) -> bytes:
        return Curve25519._base_point

    @staticmethod
    def small_subgroup_point() -> bytes:
        return Curve25519.small_subgroup_points()[2]

    @staticmethod
    def small_subgroup_points() -> list[bytes]:
        return [i.to_bytes(32, 'little') for i in Curve25519._small_subgroup_ints]

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

    def generate_known_outputs(self, public_key: bytes, private_key: bytes,
                               buffer_content: bytes) -> Iterable[tuple[bytes, int]]:
        yield from super().generate_known_outputs(public_key, private_key, buffer_content)

        # All small subgroup points have the entropy 0.
        yield from ((point, 0) for point in self.small_subgroup_points())
