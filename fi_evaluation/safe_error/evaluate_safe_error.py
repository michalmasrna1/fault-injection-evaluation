import argparse
import re
from random import randbytes

from fi_evaluation.evaluate import print_safe_error_results
from fi_evaluation.fault_finder import (Fault, SimulationResult,
                                        execute_golden_run,
                                        output_dir_from_key,
                                        print_fault_model_file,
                                        simulate_faults)
from fi_evaluation.library import Library, library_from_name
from fi_evaluation.safe_error import SafeErrorModel, safe_error_model_from_name

# How many (relative to the total number of iterations) key pairs without change to assume convergence.
CONVERGENCE_THRESHOLD_RELATIVE = 0.1
# How many (absolute) key pairs without change at least to assume convergence.
CONVERGENCE_THRESHOLD_ABSOLUTE = 5


def evaluate_safe_error(
        library: Library,
        public_key: bytes,
        safe_error_model: SafeErrorModel
):
    library = library_from_name("sca25519-unprotected", "curve25519")

    result = execute_golden_run(library)
    total_instructions = int(re.findall(r"Total instructions in faulting range:\s+(\d+)", result.stdout)[0])
    print(f"Total number of instructions: {total_instructions}")

    # Defining in advance so that we can print it after the loop.
    potentially_prone_instructions: set[SimulationResult] = set()
    prone_instructions: list[set[Fault]] = [set() for _ in range(total_instructions)]
    total_iters = 0
    unchanged_iters = 0

    while True:
        total_iters += 1
        # Safe error leakage should be present for all keys. We also
        # do not really care about the cryptographic quality of the
        # random numbers here.
        original_key = randbytes(32)
        simulate_faults(library, original_key)

        complementary_key = safe_error_model.complementary_key(original_key)
        simulate_faults(library, complementary_key)

        previous_prone_instructions = prone_instructions.copy()
        prone_instructions = [set() for _ in range(total_instructions)]

        print(f"Checking safe error on key pair {original_key.hex()}, {complementary_key.hex()}.")
        potentially_prone_instructions = library.check_safe_error(
            output_dir_from_key(library, original_key), output_dir_from_key(
                library, complementary_key), public_key, original_key, complementary_key
        )

        for simulation_result in potentially_prone_instructions:
            instruction_index_0_based = simulation_result.executed_instruction.instruction - 1
            fault = simulation_result.fault

            # on the first iteration, all pairs are assumed to be potentially prone
            if total_iters == 1 or fault in previous_prone_instructions[instruction_index_0_based]:
                # The instruction<>fault pair was prone and remains prone.
                prone_instructions[instruction_index_0_based].add(fault)

        print(f"Number of potentially prone instruction-fault pairs: {sum(len(p) for p in prone_instructions)}")
        print_fault_model_file(library, prone_instructions)

        if prone_instructions == previous_prone_instructions:
            unchanged_iters += 1
            if unchanged_iters >= CONVERGENCE_THRESHOLD_ABSOLUTE and\
                    unchanged_iters >= CONVERGENCE_THRESHOLD_RELATIVE * total_iters:
                break
        else:
            unchanged_iters = 0

    # Print the potentially prone instructions from the last run.
    # As the set of potentially prone instructions should have converged
    # by the end, this should be the final result.
    print_safe_error_results(potentially_prone_instructions, group=True)


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("library_name", type=str)
    parser.add_argument("curve_name", type=str)
    parser.add_argument("public_key", type=str)
    parser.add_argument("safe_error_model", type=str)

    args = parser.parse_args()
    library = library_from_name(args.library_name, args.curve_name)
    public_key_bytes = bytes.fromhex(args.public_key)
    safe_error_model = safe_error_model_from_name(args.safe_error_model)

    evaluate_safe_error(library, public_key_bytes, safe_error_model)


if __name__ == "__main__":
    main()
