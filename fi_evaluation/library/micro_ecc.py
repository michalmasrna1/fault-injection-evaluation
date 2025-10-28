from typing import Iterable

from fi_evaluation.curve import SECP256K1, Curve
from fi_evaluation.library import Library
from fi_evaluation.library.micro_ecc_reimplementation import (
    NUM_BITS, P, finish_ecc_point_mult, mod_sub, regularize_k, test_bit,
    xycz_add, xycz_addc, xycz_initial_double)


class MicroECC(Library):
    curve: Curve
    name = "micro-ecc"

    def __init__(self, curve: Curve):
        if not isinstance(curve, SECP256K1):
            raise ValueError("Our implementation of MicroECC only supports the secp256k1 curve.")
        super().__init__(curve)

    def generate_computational_loop_abort_results(
            self, public_key: bytes, private_key: bytes) -> Iterable[tuple[bytes, int]]:
        """
        Yields tuples of (faulted_result, entropy), where the entropy
        represents how many bits were used from the original key.
        """
        if not isinstance(self.curve, SECP256K1):
            raise ValueError("MicroECC is currently implemented only with the secp256k1 curve.")

        # This depends on the used RNG and seed.
        initial_z = 0x35ac548e96e16329beb88236c4d75c10c43ea788affcf9892871ea67b769220e
        x = int.from_bytes(public_key[0:32], "big")
        y = int.from_bytes(public_key[32:], "big")
        scalar = int.from_bytes(private_key, "big")
        k0, k1, carry = regularize_k(scalar)
        regularized_scalar = k0 if carry else k1

        # What follows in the implementation of ecc_point_mult
        # with yields of intermediate results.
        rx: list[list[int]] = [[0], [0]]
        ry: list[list[int]] = [[0], [0]]

        rx[1][0] = x
        ry[1][0] = y

        xycz_initial_double(rx[1], ry[1], rx[0], ry[0], [initial_z])
        yield rx[0][0].to_bytes(32, "big"), 0
        yield rx[1][0].to_bytes(32, "big"), 0
        sub = [mod_sub(rx[0][0], rx[1][0], P)]

        for i in range(NUM_BITS - 1, 0, -1):
            nb = int(not test_bit(regularized_scalar, i))
            xycz_addc(rx[1 - nb], ry[1 - nb], rx[nb], ry[nb], sub)
            xycz_add(rx[nb], ry[nb], rx[1 - nb], ry[1 - nb], sub)

            entropy = 1 + NUM_BITS - 1 - i
            # The intermediate results without finishing.
            yield rx[0][0].to_bytes(32, "big"), entropy
            yield rx[1][0].to_bytes(32, "big"), entropy
            # The intermediate result after finishing.
            if i > 1:
                # If i == 1, we would just yield the correct result.
                yield finish_ecc_point_mult((x, y), regularized_scalar, rx, ry, sub)[0].to_bytes(32, "big"), entropy + 1
