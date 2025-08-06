import os
import re
import subprocess
from abc import ABC, abstractmethod


class LeakageModel(ABC):
    @abstractmethod
    def complementary_key(self, original_key: bytes) -> bytes:
        """
        Generate a complementary key based on the original key.
        """


class KeyBits(LeakageModel):
    def complementary_key(self, original_key: bytes) -> bytes:
        """
        Generate a key that has the opposite bits to the original key.
        """
        return bytes(~b & 0xFF for b in original_key)


class NeighbouringBitsXor(LeakageModel):
    def complementary_key(self, original_key: bytes) -> bytes:
        """
        Generate a key for which the XOR of each pair of neighbouring bits
        is different than the XOR of the two bits on the same positions
        in the original key.
        Example:
        Original key:       00110011
        Complementary key:  10011001
        """
        bits_length = len(original_key) * 8
        original_key_int = int.from_bytes(original_key, "little")
        previous_bit_original = previous_bit_new = original_key_int & 1
        # We can choose the lowest bit freely, we choose it to be the same as
        # the original key's lowest bit.
        new_key_int = previous_bit_new
        for i in range(bits_length - 1):
            original_key_int >>= 1
            current_bit_original = original_key_int & 1
            original_xor = previous_bit_original ^ current_bit_original
            new_xor = 1 ^ original_xor
            current_bit_new = previous_bit_new ^ new_xor
            new_key_int |= current_bit_new << (i + 1)
            previous_bit_original = current_bit_original
            previous_bit_new = current_bit_new

        return new_key_int.to_bytes(len(original_key), "little")


def print_fault_model(fault_model_path: str, intervals: list[tuple[int, int]]) -> None:
    beginning_str = """######################################################################
#
######################################################################
"""
    fault_model_str = """
    Instruction Pointer:
        Op_codes: ALL
            Lifespan: 0
                Operation: SKIP
                    Masks: 1
"""
    with open(fault_model_path, "w", encoding="utf-8") as f:
        f.write(beginning_str)
        for start, end in intervals:
            # Fault finder indexes from 1
            f.write(f"Instructions: {start + 1}-{end + 1}")
            f.write(fault_model_str)


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


def replace_in_file(file_path: str, pattern: str, replacement: str) -> None:
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    # Finding the match with capture groups
    match = re.search(pattern, content)

    if match:
        # Replace the first capture group with the replacement
        new_content = content[:match.start(1)] + replacement + content[match.end(1):]

        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(new_content)


def output_dir_from_key(key: bytes) -> str:
    return f"demos/sca25519-unprotected/outputs/{key.hex()[:2]}"


def simulate_faults(key: bytes) -> None:
    output_dir = output_dir_from_key(key)
    os.makedirs(output_dir, exist_ok=True)
    replace_in_file("demos/sca25519-unprotected/jsons/fault.json",
                    r'\"output directory name\".*?\"(.*?)\"', output_dir)
    replace_in_file("demos/sca25519-unprotected/jsons/binary-details.json",
                    r'\"byte array\".*?\"(.{64})\"\s*\/\/\s*key', key.hex())

    print(f"Simulating faults for key: {key.hex()}")
    subprocess.run(["./faultfinder", "demos/sca25519-unprotected/jsons/fault.json"],
                   capture_output=True, text=True, check=False)

    print("Processing output.")
    subprocess.run(["python3", "../fault-injection-evaluation/process_output.py", output_dir, "--clean"], check=False)


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

    prone_instructions = [True for _ in range(total_instructions)]
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
        print(f"Number of potentially prone instructions: {prone_instructions.count(True)}")

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
