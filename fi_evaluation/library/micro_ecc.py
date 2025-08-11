from fi_evaluation.curve import SECP256K1, SECP256R1, Curve
from fi_evaluation.library import Library


class MicroECC(Library):
    def __init__(self, curve: Curve):
        if not isinstance(curve, (SECP256K1, SECP256R1)):
            raise ValueError("Our implementation of MicroECC only supports SECP256K1 and SECP256R1 curves.")
        super().__init__(curve, "micro-ecc")
