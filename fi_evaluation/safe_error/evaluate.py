from random import randbytes, seed

from fi_evaluation.fault_finder import (Fault, SimulationResult,
                                        get_number_of_faulted_instructions,
                                        output_dir_from_key, simulate_faults,
                                        write_fault_model_file)
from fi_evaluation.library import Library
from fi_evaluation.safe_error.leakage import SafeErrorModel

ALLOWED_RELATIVE_CHANGE = 0.0001
# How many (relative to the total number of iterations) key pairs without change at least to assume convergence.
CONVERGENCE_THRESHOLD_RELATIVE = 0.1
# How many (absolute) key pairs without change at least to assume convergence.
CONVERGENCE_THRESHOLD_ABSOLUTE = 20


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


def print_state_start(total_iters: int):
    print("################################################################################")
    print(f"Starting iteration number {total_iters}.")


def print_state_end(total_iters: int, unchanged_iters: int, relative_change: float,
                    prone_instructions: list[set[Fault]]):
    print(
        f"Number of potentially prone instruction-fault pairs: {
            count_prone_pairs(prone_instructions)}"
        f" (Changed {(100 * relative_change):.2f} % compared to the previous iteration).")
    print(f"Convergence status: {unchanged_iters}/{CONVERGENCE_THRESHOLD_ABSOLUTE}; "
          f"{unchanged_iters / total_iters if total_iters > 0 else 0:.0%}/{CONVERGENCE_THRESHOLD_RELATIVE:.0%}.")
    print("################################################################################")
    print()


def count_prone_pairs(prone_instructions: list[set[Fault]]) -> int:
    return sum(len(faults) for faults in prone_instructions)


def check_convergence(unchanged_iters: int, total_iters: int) -> bool:
    return (unchanged_iters >= CONVERGENCE_THRESHOLD_ABSOLUTE and
            unchanged_iters >= CONVERGENCE_THRESHOLD_RELATIVE * total_iters)


def evaluate_safe_error(
        library: Library,
        public_key: bytes,
        safe_error_model: SafeErrorModel,
        first_key: bytes | None = None
):
    total_instructions = get_number_of_faulted_instructions(library)
    print(f"Total number of faulted instructions: {total_instructions}")
    print()

    # Defining in advance so that we can print it after the loop.
    potentially_prone_instructions: set[SimulationResult] = set()
    prone_instructions: list[set[Fault]] = [set() for _ in range(total_instructions)]
    total_iters = 0
    unchanged_iters = 0

    # Reseed the RNG to get reproducible keys.
    seed(bytes.fromhex("ecc25519"))

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
        if total_iters == 1:
            relative_change = 1  # Avoid converging on the first iteration.
        else:
            relative_change = abs(1 - count_prone_pairs(prone_instructions) /
                                  count_prone_pairs(previous_prone_instructions))

        if relative_change < ALLOWED_RELATIVE_CHANGE:
            unchanged_iters += 1
        else:
            unchanged_iters = 0

        print_state_end(total_iters, unchanged_iters, relative_change, prone_instructions)

        if check_convergence(unchanged_iters, total_iters):
            break

    # Print the potentially prone instructions from the last run.
    # As the set of potentially prone instructions should have converged
    # by the end, this should be the final result.
    print_safe_error_results(potentially_prone_instructions, group=True)
