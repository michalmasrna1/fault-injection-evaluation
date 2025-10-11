import argparse
from random import randbytes

from fi_evaluation.evaluate import print_safe_error_results
from fi_evaluation.fault_finder import (Fault, SimulationResult,
                                        get_number_of_faulted_instructions,
                                        output_dir_from_key, simulate_faults,
                                        write_fault_model_file)
from fi_evaluation.library import Library, library_from_name
from fi_evaluation.safe_error import SafeErrorModel, safe_error_model_from_name

# How many (relative to the total number of iterations) key pairs without change at least to assume convergence.
CONVERGENCE_THRESHOLD_RELATIVE = 0.1
# How many (absolute) key pairs without change at least to assume convergence.
CONVERGENCE_THRESHOLD_ABSOLUTE = 5


def print_state_start(total_iters: int):
    print("################################################################################")
    print(f"Starting iteration number {total_iters}.")


def print_state_end(total_iters: int, unchanged_iters: int, prone_instructions: list[set[Fault]]):
    print(f"Number of potentially prone instruction-fault pairs: {sum(len(p) for p in prone_instructions)}.")
    print(f"Convergence status: {unchanged_iters}/{CONVERGENCE_THRESHOLD_ABSOLUTE}; "
          f"{unchanged_iters / total_iters if total_iters > 0 else 0:.0%}/{CONVERGENCE_THRESHOLD_RELATIVE:.0%}.")
    print("################################################################################")
    print()


def check_convergence(unchanged_iters: int, total_iters: int) -> bool:
    return (unchanged_iters >= CONVERGENCE_THRESHOLD_ABSOLUTE and
            unchanged_iters >= CONVERGENCE_THRESHOLD_RELATIVE * total_iters)


def evaluate_safe_error(
        library: Library,
        public_key: bytes,
        safe_error_model: SafeErrorModel,
        first_key: bytes | None = None
):
    library = library_from_name("sca25519-unprotected", "curve25519")

    total_instructions = get_number_of_faulted_instructions(library)
    print(f"Total number of faulted instructions: {total_instructions}")
    print()

    # Defining in advance so that we can print it after the loop.
    potentially_prone_instructions: set[SimulationResult] = set()
    prone_instructions: list[set[Fault]] = [set() for _ in range(total_instructions)]
    total_iters = 0
    unchanged_iters = 0

    while True:
        total_iters += 1
        print_state_start(total_iters)

        #
        # 1. Load/generate the key pair and run the simulations.
        #    We assume that if a key has been provided, the first-round
        #    simulation does not need to be run for the first key
        #    or its complement.
        #
        if total_iters == 1 and first_key is not None:
            original_key = first_key
            complementary_key = safe_error_model.complementary_key(original_key)
            print("Skipping simulation for the first key pair as the first key was provided.")
        else:
            # Safe error leakage should be present for all keys. We also do not
            # really care about the cryptographic quality of the random numbers here.
            original_key = randbytes(32)
            complementary_key = safe_error_model.complementary_key(original_key)
            simulate_faults(library, original_key)
            simulate_faults(library, complementary_key)

        #
        # 2. Determine potentially prone instructions for this pair.
        #
        previous_prone_instructions = prone_instructions.copy()
        prone_instructions = [set() for _ in range(total_instructions)]

        print(f"Checking safe error on key pair {original_key.hex()}, {complementary_key.hex()}.")
        potentially_prone_instructions = library.check_safe_error(
            output_dir_from_key(library, original_key),
            output_dir_from_key(library, complementary_key),
            public_key,
            original_key,
            complementary_key
        )

        #
        # 3. Update the potentially prone instructions and the fault model file accordingly.
        #
        for simulation_result in potentially_prone_instructions:
            instruction_index_0_based = simulation_result.executed_instruction.instruction - 1
            fault = simulation_result.fault

            # on the first iteration, all pairs are assumed to be potentially prone
            if total_iters == 1 or fault in previous_prone_instructions[instruction_index_0_based]:
                # The instruction<>fault pair was prone and remains prone.
                prone_instructions[instruction_index_0_based].add(fault)

        write_fault_model_file(library, prone_instructions)

        #
        # 4. Check if we have reached the convergence criteria.
        #
        if prone_instructions == previous_prone_instructions:
            unchanged_iters += 1
        else:
            unchanged_iters = 0

        print_state_end(total_iters, unchanged_iters, prone_instructions)

        if check_convergence(unchanged_iters, total_iters):
            break

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
    parser.add_argument("first_key", type=str, default=None, nargs='?')
    args = parser.parse_args()

    library = library_from_name(args.library_name, args.curve_name)
    public_key_bytes = bytes.fromhex(args.public_key)
    safe_error_model = safe_error_model_from_name(args.safe_error_model)
    first_key = bytes.fromhex(args.first_key) if args.first_key else None

    evaluate_safe_error(library, public_key_bytes, safe_error_model, first_key)


if __name__ == "__main__":
    main()
