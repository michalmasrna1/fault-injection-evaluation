from abc import ABC
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric import x25519
from fi_evaluation.curve import Curve, Curve25519
from fi_evaluation.library import Library
from pyecsca.ec.context import DefaultContext, Node, ResultAction, local
from pyecsca.ec.formula import LadderFormula, ScalingFormula
from pyecsca.ec.mult import LadderMultiplier
from pyecsca.ec.params import get_params
from pyecsca.ec.point import Point


class Sca25519(Library, ABC):
    curve: Curve
    name: str

    def __init__(self, curve: Curve = Curve25519()):
        super().__init__(curve)

    def generate_computational_loop_abort_results(
            self, public_key: bytes, private_key: bytes) -> Iterable[tuple[bytes, int]]:
        """
        All sca25519 implementations use the same algorithm
        so the loop abort results are the same for all of them.

        Yields tuples of (faulted_result, entropy), where the entropy
        represents how many bits were used from the original key.
        """
        curve25519 = get_params("other", "Curve25519", "xz", False)
        ladd = curve25519.curve.coordinate_model.formulas["ladd-1987-m-3"]
        scl = curve25519.curve.coordinate_model.formulas["scale"]
        assert isinstance(ladd, LadderFormula)
        assert isinstance(scl, ScalingFormula)

        multiplier = LadderMultiplier(ladd, scl=scl, complete=False, short_circuit=False, full=True)
        if public_key != Curve25519().base_point():
            raise NotImplementedError("Public keys other than the generator are not supported.")
        generator = curve25519.generator

        with local(DefaultContext()) as ctx:
            assert isinstance(ctx, DefaultContext)
            multiplier.init(curve25519, generator)
            multiplier.multiply(int.from_bytes(private_key, byteorder="little"))

            multiplication_node = ctx.actions[0]
            # The final two children contain the correct result
            for bit_no, child in enumerate(multiplication_node.children[:-2]):
                assert isinstance(child, Node)
                assert isinstance(child.action, ResultAction)
                action = child.action
                result_point: Point | None = None
                if len(action.result) == 2:
                    # Yield the raw intermediate result without scaling
                    yield int(str(action.result[0].coords["X"])).to_bytes(32, byteorder="little"), bit_no
                    yield int(str(action.result[1].coords["X"])).to_bytes(32, byteorder="little"), bit_no

                    # One of the ladder steps, the two results are xp and xq
                    # The correct result is determined by the last processed bit
                    # (see the last call to cswap after the computational loop)
                    correct_index = int.from_bytes(private_key, "little") >> (254 - bit_no) & 1
                    # reduce and pack the result
                    result_point = multiplier._scl(action.result[correct_index])
                elif len(action.result) == 1:
                    # The final result after the reduction (packing, scaling)
                    # We should not get here, because at this point the result is without fault
                    result_point = action.result[0]
                else:
                    raise ValueError(f"Unexpected result length: {len(action.result)}")
                assert isinstance(result_point, Point)  # result_point is not None
                yield int(str(result_point.coords["X"])).to_bytes(32, byteorder="little"), bit_no


class Sca25519Unprotected(Sca25519):
    name = "sca25519-unprotected"


class Sca25519Ephemeral(Sca25519):
    name = "sca25519-ephemeral"


class Sca25519EphemeralHardened(Sca25519):
    name = "sca25519-ephemeral-hardened"


class Sca25519Static(Sca25519):
    name = "sca25519-static"

    @staticmethod
    def compute_s_from_r_and_k(rx_bytes: bytes, k_bytes: bytes) -> tuple[bytes, bytes]:
        private_key = x25519.X25519PrivateKey.from_private_bytes(k_bytes)
        public_key = x25519.X25519PublicKey.from_public_bytes(rx_bytes)
        sx_bytes = private_key.exchange(public_key)
        sx = int.from_bytes(sx_bytes, 'little')
        rhs = (sx**3 + Curve25519.A * sx**2 + sx) % Curve25519.P
        sy = pow(rhs, (Curve25519.P + 3) // 8, Curve25519.P)
        if (sy * sy) % Curve25519.P != rhs:
            sy = (sy * pow(2, (Curve25519.P - 1) // 4, Curve25519.P)) % Curve25519.P
        if (sy * sy) % Curve25519.P != rhs:
            sy = 0
        sy_bytes = sy.to_bytes(32, 'little')
        return sx_bytes, sy_bytes

    @staticmethod
    def derive_blinded_key(original_key: bytes, blinding_factor: bytes, magic_constant: int) -> bytes:
        """
        Do not know what the magic constant is, best guess is something to do
        with how the inversions are computed. Never encountered a key where
        either 8 or -8 would not work.
        """
        clamped_key = Curve25519().preprocess_key(original_key)

        original_key_int = int.from_bytes(clamped_key, byteorder='little')

        blinding_factor_int = int.from_bytes(blinding_factor, byteorder='little') * magic_constant
        blinding_factor_inv_int = pow(blinding_factor_int, -1, Curve25519.ORDER_PRIME)

        derived_blinded_key_int = (original_key_int * blinding_factor_inv_int) % Curve25519.ORDER_PRIME
        derived_blinded_key_bytes = derived_blinded_key_int.to_bytes(32, byteorder='little')
        return derived_blinded_key_bytes
