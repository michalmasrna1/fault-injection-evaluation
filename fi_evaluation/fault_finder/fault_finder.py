import os
import re
import subprocess

from fi_evaluation.fault_finder.result import Fault, FaultType
from fi_evaluation.library import Library

FAULT_FINDER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "fault-finder")


def get_binary_details_path(library: Library) -> str:
    return os.path.join(FAULT_FINDER_DIR, "demos", library.name, "jsons", "binary-details.json")


def get_fault_json_path(library: Library) -> str:
    return os.path.join(FAULT_FINDER_DIR, "demos", library.name, "jsons", "fault.json")


def get_golden_run_json_path(library: Library) -> str:
    return os.path.join(FAULT_FINDER_DIR, "demos", library.name, "jsons", "goldenrun_full.json")


def get_fault_model_path(library: Library) -> str:
    return os.path.join(FAULT_FINDER_DIR, "demos", library.name, "faultmodels", f"{library.name}.txt")


def read_from_file(file_path: str, pattern: str) -> str:
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    if match := re.search(pattern, content):
        return match.group(1)

    raise ValueError(f"Match not found: {pattern}")


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

    fault_model_path = get_fault_model_path(library)
    with open(fault_model_path, "w", encoding="utf-8") as f:
        f.write(beginning_str)
        for instruction_number_0_based, faults in enumerate(instruction_fault_pairs):
            if not faults:
                continue

            f.write(f"Instructions: {instruction_number_0_based + 1}-{instruction_number_0_based + 1}\n")
            for fault in faults:
                f.write(fault_model_string(fault))


def output_dir_from_key(library: Library, key: bytes, absolute: bool = True) -> str:
    """
    It is better to put relative paths into FaultFinder jsons, which is why
    the relative path can be requested.
    """
    relative_path = os.path.join("demos", library.name, "outputs", key.hex())
    if absolute:
        return os.path.join(FAULT_FINDER_DIR, relative_path)
    return relative_path


def set_output_dir(library: Library, key: bytes, subdirectory: str = ""):
    """
    Optional subdirectory for example for parallel execution.
    """
    # Change dir so that we do not call makedirs with an absolute path.
    os.chdir(FAULT_FINDER_DIR)
    # Relative path is also better for the fault.json file.
    output_dir_rel = os.path.join(output_dir_from_key(library, key, False), subdirectory)
    os.makedirs(output_dir_rel, exist_ok=True)

    fault_json_path = get_fault_json_path(library)
    replace_in_file(fault_json_path, r'\"output directory name\".*?\"(.*?)\"', output_dir_rel)


def set_num_threads(library: Library, num_threads: int):
    fault_json_path = get_fault_json_path(library)
    replace_in_file(fault_json_path, r'\"threads\"\s*?:\s*?\"(\d+)\"', str(num_threads))


def set_num_checkpoints(library: Library, num_checkpoints: int):
    fault_json_path = get_fault_json_path(library)
    replace_in_file(fault_json_path, r'\"number of checkpoints\"\s*?:\s*?\"(\d+)\"', str(num_checkpoints))


def set_private_key(library: Library, key: bytes):
    binary_details_json_path = get_binary_details_path(library)
    replace_in_file(binary_details_json_path, r'\"byte array\".*?\"(.{64})\"\s*\/\/\s*private_key', key.hex())


def set_fault_range(library: Library, fault_range: range):
    fault_model_path = get_fault_model_path(library)
    replace_in_file(fault_model_path, r'Instructions:\s*(\d+)-\d+', str(fault_range.start))
    replace_in_file(fault_model_path, r'Instructions:\s*\d+-(\d+)', str(fault_range.stop))


def get_private_key(library: Library) -> bytes:
    binary_details_json_path = get_binary_details_path(library)
    key_hex = read_from_file(binary_details_json_path, r'\"byte array\".*?\"(.{64})\"\s*\/\/\s*private_key')
    return bytes.fromhex(key_hex)


def get_number_of_faulted_instructions(library: Library) -> int:
    result = execute_golden_run(library)
    total_instructions = int(re.findall(r"Total instructions in faulting range:\s+(\d+)", result.stdout)[0])
    return total_instructions


def get_number_of_checkpoints(library: Library) -> int:
    fault_json_path = get_fault_json_path(library)
    return int(read_from_file(fault_json_path, r'\"number of checkpoints\"\s*?:\s*?\"(\d+)\"'))


def get_fault_range(library: Library) -> range:
    """
    Beware, will only work correctly if a single fault range is defined.
    """
    fault_model_path = get_fault_model_path(library)
    start = int(read_from_file(fault_model_path, r'Instructions: (\d+)-\d+'))
    end = int(read_from_file(fault_model_path, r'Instructions: \d+-(\d+)'))

    # FaultFinder uses inclusive ranges, so we use that, too.
    return range(start, end)


def process_output(library: Library, key: bytes, clean: bool = True):
    print("Processing output.")
    output_dir = output_dir_from_key(library, key)
    process_output_path = os.path.join(
        FAULT_FINDER_DIR,
        "..",
        "fault-injection-evaluation",
        "fi_evaluation",
        "process_output.py")
    process_output_args = ["python3", process_output_path, output_dir]
    if clean:
        process_output_args.append("--clean")
    subprocess.run(process_output_args, check=True)


def execute_golden_run(library: Library) -> subprocess.CompletedProcess[str]:
    # The jsons are prepared so that they can be executed from inside the fault-finder directory.
    os.chdir(FAULT_FINDER_DIR)
    golden_run_path = get_golden_run_json_path(library)
    # Can't check, returns 1 even on what we consider successful execution.
    result = subprocess.run(["./faultfinder", golden_run_path], capture_output=True, text=True, check=False)

    return result


def execute_faults(library: Library) -> subprocess.CompletedProcess[str]:
    # The jsons are prepared so that they can be executed from inside the fault-finder directory.
    os.chdir(FAULT_FINDER_DIR)
    fault_json_path = get_fault_json_path(library)
    # Can't check, returns 1 even on what we consider successful execution.
    result = subprocess.run(["./faultfinder", fault_json_path], capture_output=True, text=True, check=False)

    print(result.stderr)

    return result


def simulate_faults(library: Library, key: bytes, clean: bool = True) -> None:

    set_output_dir(library, key)
    set_private_key(library, key)

    print(f"Simulating faults for key: {key.hex()}")
    execute_faults(library)
    process_output(library, key, clean)
