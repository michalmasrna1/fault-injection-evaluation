import re

from fi_evaluation.fault_finder import (Fault, execute_golden_run,
                                        output_dir_from_key,
                                        print_fault_model_file,
                                        simulate_faults)
from fi_evaluation.library import library_from_name
from fi_evaluation.safe_error.leakage import KeyBits


def main():
    model = KeyBits()
    library = library_from_name("sca25519-unprotected", "curve25519")

    result = execute_golden_run(library)
    total_instructions = int(re.findall(r"Total instructions in faulting range:\s+(\d+)", result.stdout)[0])
    print(f"Total number of instructions: {total_instructions}")

    prone_instructions: list[set[Fault]] = [set() for _ in range(total_instructions)]

    for index, original_key in enumerate([
        bytes.fromhex("11" * 32),  # bb
        bytes.fromhex("22" * 32),  # 88
        bytes.fromhex("33" * 32),  # 99
        bytes.fromhex("44" * 32),  # ee
        bytes.fromhex("55" * 32),  # ff
        bytes.fromhex("66" * 32),  # cc
        bytes.fromhex("77" * 32),  # dd
        bytes.fromhex("01" * 32),
        bytes.fromhex("23" * 32),
        bytes.fromhex("45" * 32),
        bytes.fromhex("67" * 32),
        bytes.fromhex("89" * 32),
        bytes.fromhex("ab" * 32),
        bytes.fromhex("cd" * 32),
        bytes.fromhex("ef" * 32),
    ]):
        print(f"Number of potentially prone instruction-fault pairs: {sum(len(p) for p in prone_instructions)}")

        if index > 0:
            # Skip the first printing to allow for a compact declaration of "all faults".

            print_fault_model_file(library, prone_instructions)

        simulate_faults(library, original_key)

        complementary_key = model.complementary_key(original_key)
        simulate_faults(library, complementary_key)

        previous_prone_instructions = prone_instructions.copy()
        prone_instructions = [set() for _ in range(total_instructions)]

        print(f"Checking safe error on key pair {original_key.hex()}, {complementary_key.hex()}.")
        potentially_prone_instructions = library.check_safe_error(
            output_dir_from_key(library, original_key), output_dir_from_key(library, complementary_key), bytes.fromhex(
                "0900000000000000000000000000000000000000000000000000000000000000"), original_key, complementary_key
        )
        for simulation_result in potentially_prone_instructions:
            instruction_index = simulation_result.executed_instruction.instruction
            fault = simulation_result.fault

            # if index is 0, all pairs are assumed to be potentially prone
            if index == 0 or fault in previous_prone_instructions[instruction_index]:
                # The instruction<>fault pair was prone and remains prone.
                prone_instructions[instruction_index].add(fault)


main()
