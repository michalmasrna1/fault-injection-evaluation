import os
import re
import subprocess

from fi_evaluation.fault_finder import Fault, FaultType


def replace_in_file(file_path: str, pattern: str, replacement: str) -> None:
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    if match := re.search(pattern, content):
        new_content = content[:match.start(1)] + replacement + content[match.end(1):]

        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(new_content)
    else:
        print(f"Match not found: {pattern}")


def fault_model_string(fault: Fault) -> str:
    if fault.fault_type == FaultType.SKIP:
        return f"""
    Instruction Pointer:
        Op_codes: ALL
            Lifespan: 0
                Operation: SKIP
                    Masks: {fault.mask_int}
"""
    if fault.fault_type == FaultType.FLIP:
        return f"""
    Instruction:
        Op_codes: ALL
            Lifespan: 0
                Operations: xOR
                    Masks: {int.from_bytes(fault.mask, 'big')}
"""
    if fault.fault_type == FaultType.ZERO:
        # Not implementing yet as the thesis does not use it
        raise NotImplementedError("Register clear fault_model_string not implemented.")
    raise ValueError("Unknown fault type")


def print_fault_model_file(fault_model_path: str, instruction_fault_pairs: list[set[Fault]]) -> None:
    beginning_str = """######################################################################
#
######################################################################
"""
    with open(fault_model_path, "w", encoding="utf-8") as f:
        f.write(beginning_str)
        for instruction_number, faults in enumerate(instruction_fault_pairs):
            if not faults:
                continue

            # Fault finder indexes from 1
            f.write(f"Instructions: {instruction_number + 1}-{instruction_number + 1}")
            for fault in faults:
                f.write(fault_model_string(fault))


def output_dir_from_key(key: bytes) -> str:
    return f"demos/sca25519-unprotected/outputs/{key.hex()[:2]}"


def simulate_faults(key: bytes) -> None:
    output_dir = output_dir_from_key(key)
    os.makedirs(output_dir, exist_ok=True)
    replace_in_file("demos/sca25519-unprotected/jsons/fault.json",
                    r'\"output directory name\".*?\"(.*?)\"', output_dir)
    replace_in_file("demos/sca25519-unprotected/jsons/binary-details.json",
                    r'\"byte array\".*?\"(.{64})\"\s*\/\/\s*private_key', key.hex())

    print(f"Simulating faults for key: {key.hex()}")
    subprocess.run(["./faultfinder", "demos/sca25519-unprotected/jsons/fault.json"],
                   capture_output=True, text=True, check=False)

    print("Processing output.")
    subprocess.run(["python3", "../fault-injection-evaluation/fi_evaluation/process_output.py",
                   output_dir, "--clean"], check=False)
