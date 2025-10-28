from copy import deepcopy
from typing import Iterable

from fi_evaluation.curve import SECP256K1, Curve
from fi_evaluation.library import Library
from fi_evaluation.library.sweet_b_reimplementation import (
    Context, State, point_mult_final_iteration, point_mult_iteration,
    shared_secret_finish, shared_secret_start)


class SweetB(Library):
    curve: Curve
    name = "sweet-b"

    def __init__(self, curve: Curve):
        if not isinstance(curve, SECP256K1):
            raise ValueError("The Sweet-B library only supports the secp256k1 curve.")
        super().__init__(curve)

    def generate_computational_loop_abort_results(
            self, public_key: bytes, private_key: bytes) -> Iterable[tuple[bytes, int]]:
        """
        Yields tuples of (faulted_result, entropy), where the entropy
        represents how many bits were used from the original key.
        """
        if not isinstance(self.curve, SECP256K1):
            raise ValueError("The Sweet-B library only supports the secp256k1 curve.")

        # This depends on the used RNG and seed.
        initial_z = 0x7b2dacc400b3edf840ce84a889944306f5f4421ee1cfe1a4d239ee55d04b79c0
        private_key_int = int.from_bytes(private_key)
        public_key_x = int.from_bytes(public_key[:32])
        public_key_y = int.from_bytes(public_key[32:])

        # Copy of shared_secret with yield support
        ctx = Context(
            x1=0, y1=0, x2=0, y2=0,
            t5=0, t6=0, t7=0, t8=0,
            k=0, z=0, point_x=0, point_y=0,
            state=State(i=0, swap=0, inv_k=False, k_one=False)
        )

        shared_secret_start(ctx, private_key_int, public_key_x, public_key_y, initial_z)

        yield ctx.x1.to_bytes(32), 0
        yield ctx.x2.to_bytes(32), 0
        ctx_tmp = deepcopy(ctx)
        point_mult_final_iteration(ctx_tmp)
        result = shared_secret_finish(ctx_tmp)
        yield result.to_bytes(32), 1

        while ctx.state.i > 0:
            # Consciously ignoring the 16-bit chunking.
            point_mult_iteration(ctx)
            entropy = 255 - ctx.state.i
            # Yield the raw intermediate results.
            yield ctx.x1.to_bytes(32), entropy
            yield ctx.x2.to_bytes(32), entropy

            # Skip yielding the final result when i == 0
            if ctx.state.i > 1:
                # Deep copy context and finish computation to get aborted result
                ctx_tmp = deepcopy(ctx)
                point_mult_final_iteration(ctx_tmp)
                result = shared_secret_finish(ctx_tmp)
                yield result.to_bytes(32), entropy + 1

        # No need to yield after the real finish.
