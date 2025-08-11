from typing import Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fi_evaluation.curve import Curve


class SECP256R1(Curve):
    def __init__(self):
        super().__init__("secp256r1")

    def public_key_bytes_from_private_bytes(self, private_bytes: bytes) -> bytes:

        private_key = ec.derive_private_key(int.from_bytes(private_bytes, 'big'), ec.SECP256R1())
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        return public_key_bytes

    def generate_known_outputs(self) -> Iterable[tuple[bytes, int]]:
        return []
