from typing import Iterable

from ecdsa import curves, ellipticcurve
from fi_evaluation.curve import SECP256K1, SECP256R1, Curve
from fi_evaluation.library import Library


class MicroECC(Library):
    curve: Curve
    name = "micro-ecc"

    def __init__(self, curve: Curve):
        if not isinstance(curve, (SECP256K1, SECP256R1)):
            raise ValueError("Our implementation of MicroECC only supports SECP256K1 and SECP256R1 curves.")
        super().__init__(curve)

    def generate_computational_loop_abort_results(
            self, public_key: bytes, private_key: bytes) -> Iterable[tuple[bytes, int]]:
        """
        Yields tuples of (faulted_result, entropy), where the entropy
        represents how many bits were used from the original key.
        """
        if not isinstance(self.curve, (SECP256K1, SECP256R1)):
            raise ValueError("MicroECC is currently implemented only with SECP256K1 and SECP256R1 curves.")

        curve = curves.SECP256k1.curve
        x = int.from_bytes(public_key[0:32], "big")
        y = int.from_bytes(public_key[32:], "big")
        point = ellipticcurve.Point(curve, x, y)

        results: set[tuple[bytes, int]] = set()

        for i in range(1, 256):
            # This works up to i = 128, then something weird begins to happen

            # Only use the top i bits of the private_key but do not fill with zeroes,
            # but rather shift the used key to the right as much as possible
            # The (1 << i) is or'd to the result for the initial explicit doubling.
            masked_key = ((1 << i) | (int.from_bytes(private_key[:1 + (i - 1) // 8], "big")
                                      >> ((8 - (i % 8)) % 8))).to_bytes(32, byteorder="big")

            if masked_key == private_key:
                continue

            scalar = int.from_bytes(masked_key, "big")

            for scalar_modified in (2 * scalar, 2 * scalar + 1):
                result = point * scalar_modified
                results.add((int(result.x()).to_bytes(32, "big"), i))

        return results
