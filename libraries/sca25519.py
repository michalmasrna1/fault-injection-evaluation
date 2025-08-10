from abc import ABC
from typing import Iterable

from curves.curve import Curve25519
from pyecsca.ec.context import DefaultContext, Node, ResultAction, local
from pyecsca.ec.formula import LadderFormula, ScalingFormula
from pyecsca.ec.mult import LadderMultiplier
from pyecsca.ec.params import get_params
from pyecsca.ec.point import Point

from .library import Library


class Sca25519(Library, ABC):
    def __init__(self, version_name: str):
        super().__init__(Curve25519(), f"sca25519-{version_name}")

    def generate_computational_loop_abort_results(self, key: bytes) -> Iterable[tuple[bytes, int]]:
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
        generator = curve25519.generator

        with local(DefaultContext()) as ctx:
            assert isinstance(ctx, DefaultContext)
            multiplier.init(curve25519, generator)
            multiplier.multiply(int.from_bytes(key, byteorder="little"))

            multiplication_node = ctx.actions[0]
            # The final two children contain the correct result
            for bit_no, child in enumerate(multiplication_node.children[:-2]):
                assert isinstance(child, Node)
                assert isinstance(child.action, ResultAction)
                action = child.action
                result_point: Point | None = None
                if len(action.result) == 2:
                    # One of the ladder steps, the two results are xp and xq
                    # The correct result is determined by the last processed bit
                    # (see the last call to cswap after the computational loop)
                    correct_index = int.from_bytes(key, "little") >> (254 - bit_no) & 1
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
    def __init__(self):
        super().__init__("unprotected")


class Sca25519Ephemeral(Sca25519):
    def __init__(self):
        super().__init__("ephemeral")


class Sca25519Static(Sca25519):
    def __init__(self):
        super().__init__("static")
