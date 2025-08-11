import json
import os
from abc import ABC, abstractmethod
from typing import Iterable

from fi_evaluation.key import generate_faulted_keys

root_path = os.path.dirname(os.path.abspath(__package__ or "."))
PRECOMPUTED_RESULTS_DIR = os.path.join(root_path, "key_exchange_results")


class Curve(ABC):
    name: str

    def precomputed_results_path(self, public_key: bytes) -> str:
        return os.path.join(PRECOMPUTED_RESULTS_DIR, self.name, f"{public_key.hex()}.json")

    @abstractmethod
    def shared_secret(self, public_key_bytes: bytes, private_key_bytes: bytes) -> bytes:
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
        dependent on the keys or implementation details.
        """

    def generate_faulted_results(self, public_key: bytes,
                                 original_private_key: bytes) -> Iterable[tuple[bytes, bytes, int]]:
        key_result_dict: dict[str, str] = {}
        if os.path.exists(self.precomputed_results_path(public_key)):
            with open(self.precomputed_results_path(public_key), encoding='utf-8') as f:
                key_result_dict = json.loads(f.read())

        for faulted_key, entropy in generate_faulted_keys(original_private_key):
            preprocessed_key = self.preprocess_key(faulted_key)

            if preprocessed_key == original_private_key:
                # Skip "faulted" keys equal to the original key for clearer output.
                continue

            if preprocessed_key.hex() in key_result_dict:
                shared_secret = bytes.fromhex(key_result_dict[preprocessed_key.hex()])
            else:
                try:
                    shared_secret = self.shared_secret(public_key, preprocessed_key)
                except ValueError:
                    # The key is invalid for the given curve (e. g. all 0), we skip it.
                    continue
                key_result_dict[preprocessed_key.hex()] = shared_secret.hex()

            yield preprocessed_key, shared_secret, entropy

        # Save the precomputed multiplication results so that they not need to be computed again.
        if not os.path.exists(os.path.dirname(self.precomputed_results_path(public_key))):
            os.makedirs(os.path.dirname(self.precomputed_results_path(public_key)), exist_ok=True)

        with open(self.precomputed_results_path(public_key), 'w', encoding='utf-8') as f:
            f.write(json.dumps(key_result_dict))
