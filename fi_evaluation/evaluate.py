import argparse
import os

from fi_evaluation.fault_finder import (Fault, SimulationResult,
                                        print_sorted_simulation_results,
                                        simulate_faults_parallel)
from fi_evaluation.library import PredictableOutputs, library_from_name

EXECUTABLE_DIR = os.path.dirname(os.path.abspath(__file__))


def print_predictable_outputs(predictable_outputs: PredictableOutputs, type_name: str):
    """
    Print the predictable outputs sorted by their entropy.
    A smaller entropy means easier to guess key/output - a bigger problem.
    type_name represents the type of predictable outputs, e.g. "Known output" or "Faulted key".
    """
    for output, (entropy, results) in sorted(predictable_outputs.items(), key=lambda item: item[1][0]):
        print(f"{type_name} - {output.hex()} ({entropy}).")
        print_sorted_simulation_results(results)
    print()


def print_safe_error_results(potentially_prone_addresses: set[SimulationResult], group: bool = False):
    if not group:
        for result in sorted(potentially_prone_addresses):
            print(result)
        return

    # Construct a dict mapping each (address, hit) pair to the instruction number
    address_hit_to_inst: dict[tuple[bytes, int], int] = {}
    for result in potentially_prone_addresses:
        address_hit_to_inst[(result.executed_instruction.address,
                             result.executed_instruction.hit)] = result.executed_instruction.instruction

    # First, construct a set of Faults for each address<>hit pair.
    address_hit_to_faults: dict[tuple[bytes, int], set[Fault]] = {}
    for result in potentially_prone_addresses:
        key = (result.executed_instruction.address, result.executed_instruction.hit)
        if key not in address_hit_to_faults:
            address_hit_to_faults[key] = set()
        address_hit_to_faults[key].add(result.fault)

    # for each address, group the hits by the set of faults this address<>hit
    # pair is prone to.
    grouped_results: dict[bytes, dict[frozenset[Fault], set[int]]] = {}
    for (address, hit), faults in address_hit_to_faults.items():
        if address not in grouped_results:
            grouped_results[address] = {}
        if frozenset(faults) not in grouped_results[address]:
            grouped_results[address][frozenset(faults)] = set()
        grouped_results[address][frozenset(faults)].add(hit)

    for address, faults_to_hits in sorted(grouped_results.items()):
        print(f"Address {address.hex()}:")
        for faults, hits in faults_to_hits.items():
            hits_string = ", ".join(f"{i} ({address_hit_to_inst[(address, i)]})" for i in sorted(hits))
            print(f"  Hit{'s' if len(hits) > 1 else ''} {hits_string}:")
            for fault in sorted(faults):
                print(f"    {fault}")
        print()


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    parser_check_predictable = subparsers.add_parser("check-predictable")
    parser_check_predictable.add_argument("library_name", type=str)
    parser_check_predictable.add_argument("curve_name", type=str)
    parser_check_predictable.add_argument("output_dir", type=str)
    parser_check_predictable.add_argument("public_key", type=str)
    parser_check_predictable.add_argument("private_key", type=str)

    parser_check_safe_error = subparsers.add_parser("check-safe-error")
    parser_check_safe_error.add_argument("library_name", type=str)
    parser_check_safe_error.add_argument("curve_name", type=str)
    parser_check_safe_error.add_argument("output_dir_1", type=str)
    parser_check_safe_error.add_argument("output_dir_2", type=str)
    parser_check_safe_error.add_argument("public_key", type=str)
    parser_check_safe_error.add_argument("private_key_1", type=str)
    parser_check_safe_error.add_argument("private_key_2", type=str)

    parser_simulate_parallel = subparsers.add_parser("simulate-parallel")
    parser_simulate_parallel.add_argument("library_name", type=str)
    parser_simulate_parallel.add_argument("curve_name", type=str)
    parser_simulate_parallel.add_argument("optimal_threads", type=int, nargs='?', default=None)

    args = parser.parse_args()
    library = library_from_name(args.library_name, args.curve_name)

    if args.command == "check-predictable":
        public_key_bytes = bytes.fromhex(args.public_key)
        private_key_bytes = bytes.fromhex(args.private_key)
        library.check_predictable_outputs(args.output_dir, public_key_bytes, private_key_bytes)

    elif args.command == "check-safe-error":
        public_key_bytes = bytes.fromhex(args.public_key)
        private_key_1_bytes = bytes.fromhex(args.private_key_1)
        private_key_2_bytes = bytes.fromhex(args.private_key_2)
        potentially_prone_addresses = library.check_safe_error(
            args.output_dir_1,
            args.output_dir_2,
            public_key_bytes,
            private_key_1_bytes,
            private_key_2_bytes)
        print_safe_error_results(potentially_prone_addresses, group=True)

    # TODO: Not sure if this should be here, this is not really an evaluation
    # so calling "evaluate.py simulate-parallel" is not really correct.
    elif args.command == "simulate-parallel":
        if args.optimal_threads is None:
            simulate_faults_parallel(library)
        else:
            simulate_faults_parallel(library, args.optimal_threads)


if __name__ == "__main__":
    main()
