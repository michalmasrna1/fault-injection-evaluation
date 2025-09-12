import os
import re
import subprocess

from fi_evaluation.fault_finder.result import Fault, FaultType
from fi_evaluation.library import Library

FAULT_FINDER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "fault-finder")


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
        return f"""    Instruction Pointer:
        Op_codes: ALL
            Lifespan: 0
                Operation: SKIP
                    Masks: {fault.mask_int}
"""
    if fault.fault_type == FaultType.FLIP:
        return f"""    Instruction:
        Op_codes: ALL
            Lifespan: 0
                Operations: xOR
                    Masks: 1<{fault.mask_int}<{fault.mask_int + 1}
"""
    if fault.fault_type == FaultType.ZERO:
        # Not implementing yet as the thesis does not use it.
        # For the format, see
        # https://github.com/michalmasrna1/fault-finder/commit/796928fa6e1b0ec906a216d1592a525b1e96ac28
        raise NotImplementedError("Register clear fault_model_string not implemented.")
    raise ValueError("Unknown fault type")


def print_fault_model_file(library: Library, instruction_fault_pairs: list[set[Fault]]) -> None:
    beginning_str = """######################################################################
#
######################################################################
"""

    fault_model_path = os.path.join("demos", library.name, "faultmodels", f"{library.name}.txt")
    with open(fault_model_path, "w", encoding="utf-8") as f:
        f.write(beginning_str)
        for instruction_number_0_based, faults in enumerate(instruction_fault_pairs):
            if not faults:
                continue

            f.write(f"Instructions: {instruction_number_0_based + 1}-{instruction_number_0_based + 1}\n")
            for fault in faults:
                f.write(fault_model_string(fault))


def output_dir_from_key(library: Library, key: bytes) -> str:
    return os.path.join("demos", library.name, "outputs", key.hex())


def execute_golden_run(library: Library) -> subprocess.CompletedProcess[str]:
    # The jsons are prepared so that they can be executed from inside the fault-finder directory.
    os.chdir(FAULT_FINDER_DIR)
    print("Executing the golden run.")
    golden_run_path = f"demos/{library.name}/jsons/goldenrun_full.json"
    # Can't check, returns 1 even on what we consider successful execution.
    result = subprocess.run(["./faultfinder", golden_run_path], capture_output=True, text=True, check=False)

    return result


def simulate_faults(library: Library, key: bytes) -> None:
    # The jsons are prepared so that they can be executed from inside the fault-finder directory.
    os.chdir(FAULT_FINDER_DIR)

    output_dir = output_dir_from_key(library, key)
    os.makedirs(output_dir, exist_ok=True)

    fault_json_path = os.path.join("demos", library.name, "jsons", "fault.json")
    replace_in_file(fault_json_path, r'\"output directory name\".*?\"(.*?)\"', output_dir)

    binary_details_path = os.path.join("demos", library.name, "jsons", "binary-details.json")
    replace_in_file(binary_details_path, r'\"byte array\".*?\"(.{64})\"\s*\/\/\s*private_key', key.hex())

    print(f"Simulating faults for key: {key.hex()}")
    # Can't check, returns 1 even on what we consider successful execution.
    subprocess.run(["./faultfinder", fault_json_path], capture_output=True, text=True, check=False)

    print("Processing output.")
    subprocess.run(["python3", "../fault-injection-evaluation/fi_evaluation/process_output.py",
                    output_dir, "--clean"], check=True)
