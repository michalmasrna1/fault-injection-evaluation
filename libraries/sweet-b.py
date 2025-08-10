from curve import SECP256K1, SECP256R1, Curve

from .library import Library


class SweetB(Library):
    def __init__(self, curve: Curve):
        if not isinstance(curve, (SECP256K1, SECP256R1)):
            raise ValueError("The Sweet-B library only supports SECP256K1 and SECP256R1 curves.")
        super().__init__(curve, "sweet-b")
