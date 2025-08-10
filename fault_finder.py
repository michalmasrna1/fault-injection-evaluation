import os
import re
import subprocess


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
