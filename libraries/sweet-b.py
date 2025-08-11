from typing import Iterable

from curves.curve import SECP256K1, SECP256R1, Curve
from libraries.library import Library
from pyecsca.ec.params import get_params


class SweetB(Library):
    def __init__(self, curve: Curve):
        if not isinstance(curve, (SECP256K1, SECP256R1)):
            raise ValueError("The Sweet-B library only supports SECP256K1 and SECP256R1 curves.")
        super().__init__(curve, "sweet-b")

    def generate_computational_loop_abort_results(self, key: bytes) -> Iterable[tuple[bytes, int]]:
        """
        Yields tuples of (faulted_result, entropy), where the entropy
        represents how many bits were used from the original key.
        """
        if not isinstance(self.curve, (SECP256K1, SECP256R1)):
            raise ValueError("The Sweet-B library only supports SECP256K1 and SECP256R1 curves.")

        params = get_params("secg", self.curve.name, "xz", False)  # TODO: Figure out what "coords" to use
        # TODO: Finish the implementation
        return []
