import os
import re
import sys
from multiprocessing import Process

from fi_evaluation.fault_finder.result import (NO_OUTPUT, ExecutedInstruction,
                                               Fault, FaultTarget, FaultType,
                                               SimulationResult)


def find_in_entry(entry: str, pattern: str, default: str | None = None) -> str:
    match = re.search(pattern, entry)
    if not match:
        if default is not None:
            return default
        raise ValueError(f"Invalid entry, no match for pattern '{pattern}': {entry}")
    return match.group(1)


def fault_from_entry(entry: str) -> Fault:
    # Look for the fields Faulting Target: and Operation:,
    # based on that, extract the relevant fields.
    target_str = find_in_entry(entry, r'Faulting Target: (.+?)\.')

    if target_str == "InstructionPointer":
        fault_type = FaultType.SKIP
        target = FaultTarget.PC
        skipped_instruction = find_in_entry(entry, r'Number of skipped instructions: (\d+).')
        mask = int(skipped_instruction).to_bytes(8, 'little')
        old_value = find_in_entry(entry, r'Original IP\s*?:\s*?0x([a-f0-9]+?)\s')
        new_value = find_in_entry(entry, r'Updated IP\s*?:\s*?0x([a-f0-9]+?)\s')
    elif target_str == "Instruction":
        fault_type = FaultType.FLIP
        target = FaultTarget.IR
        mask = bytes.fromhex(find_in_entry(entry, r'Mask: ([a-f0-9]+?).'))
        old_value = find_in_entry(entry, r'Original instruction\s*?:\s*?(([a-f0-9]{2} ){2,4})\s')
        new_value = find_in_entry(entry, r'Updated instruction\s*?:\s*?(([a-f0-9]{2} ){2,4})\s')
    elif target_str == "Register":
        fault_type = FaultType.ZERO
        register_number = find_in_entry(entry, r'Reg#: (.+?)\.')
        target = eval(f"FaultTarget.{register_number}")  # pylint: disable=W0123 (eval-used)
        mask = b'\xff\xff\xff\xff\xff\xff\xff\xff'  # All bits are affected
        old_value = find_in_entry(entry, r'Original register\s*?:\s*?0x([a-f0-9]+?)\s')
        new_value = find_in_entry(entry, r'Updated\s*?:\s*?0x([a-f0-9]+?)\s')
    else:
        raise ValueError(f"Invalid entry, unknown target: {target_str}")
    old_value = bytes.fromhex(f"{old_value.replace(' ', ''):0>8}")
    new_value = bytes.fromhex(f"{new_value.replace(' ', ''):0>8}")

    return Fault(
        fault_type=fault_type,
        target=target,
        mask=mask,
        old_value=old_value,
        new_value=new_value
    )


def executed_instruction_from_entry(entry: str) -> ExecutedInstruction:
    address = find_in_entry(entry, r'Address: 0x([a-f0-9]+?)\.')
    hit = find_in_entry(entry, r'Hit: (\d+).')
    instruction = find_in_entry(entry, r'Instruction: (\d+).')

    return ExecutedInstruction(
        address=bytes.fromhex(f"{address.strip():0>8}"),
        hit=int(hit),
        instruction=int(instruction)
    )


def simulation_result_from_entry(entry: str) -> SimulationResult:
    fault = fault_from_entry(entry)
    executed_instruction = executed_instruction_from_entry(entry)

    errored = find_in_entry(entry, r'(Errored:)', default="") != "" or \
        find_in_entry(entry, r'(Run result: fault errored program)', default="") != ""

    # If the execution errored there might be no output
    output_str = find_in_entry(entry, r'Output.+?: ([a-f0-9]+?)\s', default="")
    if output_str:
        output = bytes.fromhex(output_str.strip())
    else:
        output = NO_OUTPUT

    return SimulationResult(
        executed_instruction=executed_instruction,
        fault=fault,
        errored=errored,
        output=output
    )


def process_output(original_path: str, destination_path: str, clean: bool) -> None:
    with open(original_path, encoding="utf-8") as original_file:
        output = original_file.read()

    with open(destination_path, "wb") as destination_file:
        entries = output.split("#####")
        for entry in entries:
            if not entry.strip():
                # Skip empty entries (the initial new lines)
                continue

            result = simulation_result_from_entry(entry)

            destination_file.write(result.to_bytes())

    if clean:
        # Moved here so that the file is not deleted
        # if an exception has been raised.
        os.remove(original_path)


def process_outputs(output_dir: str, clean: bool = False) -> None:
    """
    Convert all output files in the given directory from text to binary.
    The processing is executed in parallel.
    """
    processes: list[Process] = []

    for file_name in os.listdir(output_dir):
        if not file_name.endswith(".txt"):
            continue
        original_path = os.path.join(output_dir, file_name)
        destination_path = os.path.join(output_dir, file_name.replace(".txt", ".bin"))
        process = Process(target=process_output, args=(original_path, destination_path, clean))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()


def main():
    if len(sys.argv) < 2:
        print("Usage: python process_output.py <output_dir> [--clean]")
        return
    output_dir = sys.argv[1]
    clean = "--clean" in sys.argv
    if not os.path.isdir(output_dir):
        print(f"Error: {output_dir} is not a directory.")
        return
    process_outputs(output_dir, clean)


if __name__ == "__main__":
    main()
