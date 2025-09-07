import argparse
import os

from fi_evaluation.fault_finder import (SimulationResult,
                                        print_sorted_simulation_results)
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


def print_safe_error_results(potentially_prone_addresses: set[SimulationResult]):
    print("Addresses potentially prone to safe error attack:")
    for result in sorted(potentially_prone_addresses):
        print(result)


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
        print_safe_error_results(potentially_prone_addresses)


if __name__ == "__main__":
    main()
