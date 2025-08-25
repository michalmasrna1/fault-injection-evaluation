import os
import re
import subprocess

from fi_evaluation.fault_finder.fault_finder import (output_dir_from_key,
                                                     print_fault_model_file,
                                                     simulate_faults)
from fi_evaluation.fault_finder.result import Fault, FaultTarget, FaultType
from fi_evaluation.safe_error.leakage import KeyBits


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
            print_fault_model_file(
                "demos/sca25519-unprotected/faultmodels/sca25519-unprotected.txt",
                prone_instructions)

        simulate_faults(original_key)

        complementary_key = model.complementary_key(original_key)
        simulate_faults(complementary_key)

        print(f"Executing evaluate.py on key pair {original_key.hex()}, {complementary_key.hex()}.")
        result = subprocess.run(["python3", "../fault-injection-evaluation/fi_evaluation/evaluate.py",
                                 "check-safe-error", "sca25519-unprotected", "curve25519", output_dir_from_key(
                                     original_key), output_dir_from_key(complementary_key),
                                 "0900000000000000000000000000000000000000000000000000000000000000",
                                 original_key.hex(), complementary_key.hex()],
                                check=False, capture_output=True, text=True)
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr)

        previous_prone_instructions = prone_instructions.copy()
        prone_instructions = [set() for _ in range(total_instructions)]

        for line in result.stdout.splitlines()[1:]:  # Ignore the initial line
            inst_num_match = re.findall(r'\((\d+?)\)', line)
            # This should be moved to a better place, this should not be dependent
            # on the details of the printing.
            if type_match := re.findall(r'Skipped (\d+) instructions?', line):
                mask = int(type_match[0]).to_bytes(4, 'big')
                fault_type = FaultType.SKIP
                fault_target = FaultTarget.PC
            elif type_match := re.findall(r'Flipped instruction bit (\d+?)', line):
                mask = (1 << (int(type_match[0]) - 1)).to_bytes(4, 'big')
                fault_type = FaultType.FLIP
                fault_target = FaultTarget.IR
            else:
                print(f"Invalid safe error result line: {line}")
                continue

            instruction_index = int(inst_num_match[0]) - 1  # Fault finder indexes from 1

            # We ignore the old_value and new_value during safe error evaluation
            fault = Fault(fault_type, fault_target, mask, b"\x00" * 4, b"\x00" * 4)

            # if index is 0, all pairs are assumed to be potentially prone
            if index == 0 or fault in previous_prone_instructions[instruction_index]:
                # The instruction<>fault pair was prone and remains prone.
                prone_instructions[instruction_index].add(fault)


main()
