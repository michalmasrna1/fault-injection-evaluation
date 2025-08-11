from fi_evaluation.curve.curve import Curve
from fi_evaluation.curve.curve25519 import Curve25519
from fi_evaluation.curve.secp256k1 import SECP256K1
from fi_evaluation.curve.secp256r1 import SECP256R1


def curve_from_name(name: str) -> Curve:
    for curve in (Curve25519, SECP256K1, SECP256R1):
        if curve.name.lower() == name.lower():
            return curve()
    raise ValueError(f"Unknown curve name: {name}.")
