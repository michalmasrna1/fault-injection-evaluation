import os
import re
import subprocess

from fault_finder.fault_finder import (output_dir_from_key, print_fault_model,
                                       simulate_faults)
from fault_finder.result import FaultTarget, FaultType
from leakage import KeyBits


def intervals_from_list(instructions: list[bool]) -> list[tuple[int, int]]:
    intervals: list[tuple[int, int]] = []
    previous_true = None
    for i, current in enumerate(instructions):
        if current and previous_true is None:
            previous_true = i
        elif not current and previous_true is not None:
            intervals.append((previous_true, i - 1))
            previous_true = None
    if previous_true is not None:
        intervals.append((previous_true, len(instructions) - 1))
    return intervals


def main():
    model = KeyBits()

    # The jsons are prepared so that they can be executed from inside the
    # fault-finder directory.
    os.chdir("../fault-finder")
    print("Executing the golden run.")
    result = subprocess.run(["./faultfinder", "demos/sca25519-unprotected/jsons/goldenrun_full.json"],
                            capture_output=True, text=True, check=False)

    total_instructions = int(re.findall(r"Total instructions in faulting range:\s+(\d+)", result.stdout)[0])
    print(f"Total number of instructions: {total_instructions}")

    prone_instructions: list[set[tuple[FaultType, FaultTarget]]] = [set() for _ in range(total_instructions)]
    previous_prone_instructions = prone_instructions.copy()

    for original_key in [
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
    ]:
        print(f"Number of potentially prone instruction-fault pairs: {sum(len(p) for p in prone_instructions)}")

        instruction_intervals = intervals_from_list(prone_instructions)
        print_fault_model("demos/sca25519-unprotected/faultmodels/sca25519-unprotected.txt", instruction_intervals)

        simulate_faults(original_key)

        complementary_key = model.complementary_key(original_key)
        simulate_faults(complementary_key)

        print(f"Executing evaluate.py on key pair {original_key.hex()}, {complementary_key.hex()}.")
        result = subprocess.run(["python3", "../fault-injection-evaluation/evaluate.py", "check-safe-error",
                                 output_dir_from_key(original_key), output_dir_from_key(complementary_key),
                                 original_key.hex(), complementary_key.hex(),],
                                check=False, capture_output=True, text=True)

        previous_prone_instructions = prone_instructions.copy()
        prone_instructions = [False for _ in range(total_instructions)]
        for match in re.finditer(r'\((\d+?)\)', result.stdout):
            instruction_index = int(match.group(1)) - 1  # Fault finder indexes from 1
            if previous_prone_instructions[instruction_index]:
                # The instruction was prone and remains prone.
                prone_instructions[instruction_index] = True


main()
