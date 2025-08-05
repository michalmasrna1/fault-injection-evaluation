import json
import os
from abc import ABC, abstractmethod
from typing import Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from key import generate_faulted_keys


class Curve(ABC):
    precomputed_results_path: str

    def __init__(self, precomputed_results_path: str):
        self.precomputed_results_path = precomputed_results_path

    @abstractmethod
    def public_key_bytes_from_private_bytes(self, private_bytes: bytes) -> bytes:
        pass

    def preprocess_key(self, key: bytes) -> bytes:
        """
        Process the key before using it. An example of such preprocessing
        is clamping the key before using it with curve25519.
        """
        return key

    @abstractmethod
    def generate_known_outputs(self) -> Iterable[tuple[bytes, int]]:
        """
        Generate known outputs specific for the curve, which are not
        dependent on the key or implementation details.
        """

    def generate_faulted_results(self, original_key: bytes) -> Iterable[tuple[bytes, bytes, int]]:
        key_result_dict: dict[str, str] = {}
        if os.path.exists(self.precomputed_results_path):
            with open(self.precomputed_results_path, encoding='utf-8') as f:
                key_result_dict = json.loads(f.read())

        for faulted_key, entropy in generate_faulted_keys(original_key):
            preprocessed_key = self.preprocess_key(faulted_key)

            if preprocessed_key == original_key:
                # Skip "faulted" keys equal to the original key for clearer output.
                continue

            if preprocessed_key.hex() in key_result_dict:
                resulting_public_key = bytes.fromhex(key_result_dict[preprocessed_key.hex()])
            else:
                resulting_public_key = self.public_key_bytes_from_private_bytes(preprocessed_key)
                key_result_dict[preprocessed_key.hex()] = resulting_public_key.hex()

            yield preprocessed_key, resulting_public_key, entropy

        # Save the precomputed multiplication results so that they not need to be computed again.
        if not os.path.exists(os.path.dirname(self.precomputed_results_path)):
            os.makedirs(os.path.dirname(self.precomputed_results_path), exist_ok=True)

        with open(self.precomputed_results_path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(key_result_dict))


class Curve25519(Curve):
    def public_key_bytes_from_private_bytes(self, private_bytes: bytes) -> bytes:
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        return public_key_bytes

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
