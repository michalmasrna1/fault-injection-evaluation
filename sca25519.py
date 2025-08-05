import argparse
import os
from typing import Iterable

from curve import *
from pyecsca.ec.context import DefaultContext, Node, ResultAction, local
from pyecsca.ec.formula import LadderFormula, ScalingFormula
from pyecsca.ec.mult import LadderMultiplier
from pyecsca.ec.params import get_params
from pyecsca.ec.point import Point
from result import *

EXECUTABLE_DIR = os.path.dirname(os.path.abspath(__file__))


# Also should probably be defined in some common IO file
def parse_known_outputs(known_outputs_path: str) -> dict[bytes, int]:
    known_outputs: dict[bytes, int] = {}

    with open(known_outputs_path, "r") as f:
        for line in f.read().splitlines():
            output_str, entropy_str = line.split(",")
            known_outputs[bytes.fromhex(output_str)] = int(entropy_str)

    return known_outputs


# This is a method of a library - we need to know both the curve
# and the implementation details
def generate_computational_loop_abort_results(key: bytes) -> Iterable[tuple[bytes, int]]:
    """
    Returns tuples of (faulted_result, entropy), where the entropy
    represents how many bits were used from the original key.
    """
    curve25519 = get_params("other", "Curve25519", "xz", infty=False)
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
            assert isinstance(result_point, Point) # result_point is not None
            yield int(str(result_point.coords["X"])).to_bytes(32, byteorder="little"), bit_no


# Probably a common method of the libraries
def check_key_shortening(parsed_output: list[SimulationResult], key: bytes, curve: Curve):
    results_sim: dict[bytes, set[SimulationResult]] = {}
    for result_sim in parsed_output:
        if result_sim.output is None:
            continue
        if result_sim.output not in results_sim:
            results_sim[result_sim.output] = set()
        results_sim[result_sim.output].add(result_sim)

    seen_effective_keys: dict[bytes, tuple[int, set[SimulationResult]]] = {}
    for faulted_key, result, entropy in curve.generate_faulted_results(key):
        if result in results_sim:
            if faulted_key in seen_effective_keys:
                if entropy < seen_effective_keys[faulted_key][0]:
                    # The same key might have been generated with different entropies.
                    # We care about the smallest one.
                    seen_effective_keys[faulted_key] = (entropy, seen_effective_keys[faulted_key][1])
            else:
                seen_effective_keys[faulted_key] = (entropy, results_sim[result])

    # Order by the entropy of the faulted key.
    # Smaller entropy means easier to guess faulted key - a bigger problem.
    for faulted_key, (entropy, results) in sorted(seen_effective_keys.items(), key=lambda item: item[1][0]):
        print(f"Faulted key - {faulted_key.hex()} ({entropy}).")
        print_sorted_simulation_results(results)
        print()


# A common method of the libraries
def check_known_outputs(parsed_output: list[SimulationResult], known_outputs: dict[bytes, int]):
    seen_known_outputs: dict[bytes, tuple[int, set[SimulationResult]]] = {}
    for result_sim in parsed_output:
        output = result_sim.output
        if output in known_outputs:
            entropy = known_outputs[output]
            if output not in seen_known_outputs:
                seen_known_outputs[output] = (entropy, {result_sim})
            else:
                if entropy < seen_known_outputs[output][0]:
                    # The same known output might have been generated with different entropies.
                    # We care about the smallest one.
                    seen_known_outputs[output] = (entropy, {result_sim})
                else:
                    seen_known_outputs[output][1].add(result_sim)

    for output, (entropy, results) in sorted(seen_known_outputs.items(), key=lambda item: item[1][0]):
        print(f"Known output - {output.hex()} ({entropy}).")
        print_sorted_simulation_results(results)
        print()
        

# A method of the library
def generate_known_outputs(key: bytes, known_outputs_path: str):
    if not os.path.exists(known_outputs_path):
        os.makedirs(os.path.dirname(known_outputs_path), exist_ok=True)

    with open(known_outputs_path, "w") as known_outputs_file:
        # TODO: call curve.generate_known_outputs()

        for computational_loop_abort_key, entropy in generate_computational_loop_abort_results(key):
            known_outputs_file.write(f"{computational_loop_abort_key.hex()},{entropy}\n")


# Probably a common method of the libraries
def check_predictable_outputs(output_dir: str, key: bytes, known_outputs_path: str, curve: Curve):
    parsed_output = list(read_processed_outputs(output_dir))  # Need to cast to a list to be able to iterate multiple times
    check_key_shortening(parsed_output, key, curve)
    known_outputs = parse_known_outputs(known_outputs_path)
    check_known_outputs(parsed_output, known_outputs)


# Probably a common method of the libraries
def check_safe_error(output_dir_1: str, output_dir_2: str, key_1: bytes, key_2: bytes, curve: Curve):
    results_sim_1 = list(read_processed_outputs(output_dir_1))
    results_sim_2 = list(read_processed_outputs(output_dir_2))
    print(f"Number of fault results: {len(results_sim_1)}, {len(results_sim_2)}")
    print()
    # Any value definitely larger than the total number of instructions
    results_sim_1_ordered: list[SimulationResult | None] = [None for _ in range(1_000_000)]
    results_sim_2_ordered: list[SimulationResult | None] = [None for _ in range(1_000_000)]
    for result_sim_1_tmp in results_sim_1:
        results_sim_1_ordered[result_sim_1_tmp.executed_instruction.instruction] = result_sim_1_tmp
    for result_sim_2_tmp in results_sim_2:
        results_sim_2_ordered[result_sim_2_tmp.executed_instruction.instruction] = result_sim_2_tmp
    
    correct_result_1 = curve.public_key_bytes_from_private_bytes(key_1)
    correct_result_2 = curve.public_key_bytes_from_private_bytes(key_2)

    potentially_prone_addresses: dict[bytes, set[int]] = {}
    for result_sim_1, result_sim_2 in zip(
            results_sim_1_ordered, results_sim_2_ordered):
        if result_sim_1 is None or result_sim_2 is None:
            continue
        assert result_sim_1.executed_instruction.address == result_sim_2.executed_instruction.address
        assert result_sim_1.executed_instruction.hit == result_sim_2.executed_instruction.hit
        assert result_sim_1.executed_instruction.instruction == result_sim_2.executed_instruction.instruction

        if (result_sim_1.output == correct_result_1) ^ (result_sim_2.output == correct_result_2):
            if result_sim_1.executed_instruction.address not in potentially_prone_addresses:
                potentially_prone_addresses[result_sim_1.executed_instruction.address] = set()
            potentially_prone_addresses[result_sim_1.executed_instruction.address].add(result_sim_1.executed_instruction.hit)

    print("Addresses potentially prone to safe error attack:")
    for address, hits in sorted(potentially_prone_addresses.items()):
        print(f"{address.hex()} on hits ({', '.join(map(str, sorted(hits)))})")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    parser_check_key_shortening = subparsers.add_parser("generate-known-outputs")
    parser_check_key_shortening.add_argument("key", type=str)
    parser_check_key_shortening.add_argument("known_outputs_path", type=str)

    parser_check_predictable = subparsers.add_parser("check-predictable")
    parser_check_predictable.add_argument("output_dir", type=str)
    parser_check_predictable.add_argument("key", type=str)
    parser_check_predictable.add_argument("known_outputs_path", type=str)

    parser_check_safe_error = subparsers.add_parser("check-safe-error")
    parser_check_safe_error.add_argument("output_dir_1", type=str)
    parser_check_safe_error.add_argument("output_dir_2", type=str)
    parser_check_safe_error.add_argument("key_1", type=str)
    parser_check_safe_error.add_argument("key_2", type=str)

    args = parser.parse_args()
    curve = Curve25519("faulted_results.json")
    if args.command == "generate-known-outputs":
        key_bytes = bytes.fromhex(args.key)
        generate_known_outputs(key_bytes, args.known_outputs_path)
    if args.command == "check-predictable":
        key_bytes = bytes.fromhex(args.key)
        check_predictable_outputs(args.output_dir, key_bytes, args.known_outputs_path, curve)
    elif args.command == "check-safe-error":
        key_1_bytes = bytes.fromhex(args.key_1)
        key_2_bytes = bytes.fromhex(args.key_2)
        check_safe_error(args.output_dir_1, args.output_dir_2, key_1_bytes, key_2_bytes, curve)


if __name__ == "__main__":
    main()
