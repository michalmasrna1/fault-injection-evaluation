import os
import re
import subprocess
from datetime import datetime
from multiprocessing import Pool
from time import sleep

from dotenv import load_dotenv
from fi_evaluation.fault_finder.process_output import process_outputs
from fi_evaluation.fault_finder.result import Fault, FaultType
from fi_evaluation.library import Library

# Read the env variable FAULT_FINDER_PATH.
# 1. If it is an absolute path, use it directly.
# 2. If it is a relative path, interpret it as relative to the base of this repository.
# 3. If the env variable is not set, use ../fault-finder, assuming the fault-finder
#    directory resides directly next to this repository.
load_dotenv()
FAULT_FINDER_PATH = os.environ.get("FAULT_FINDER_PATH", os.path.join("..", "fault-finder-default"))
FAULT_FINDER_DIR = FAULT_FINDER_PATH if os.path.isabs(FAULT_FINDER_PATH) else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", FAULT_FINDER_PATH
)
if not os.path.isdir(FAULT_FINDER_DIR):
    raise ValueError(f"FAULT_FINDER_PATH does not point to a valid directory: {FAULT_FINDER_DIR}")


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


def write_fault_model_file(library: Library, instruction_fault_pairs: list[set[Fault]]) -> None:
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
    return result


def simulate_faults(library: Library, key: bytes, clean: bool = True) -> None:
    set_output_dir(library, key)
    set_private_key(library, key)

    print(f"Simulating faults for key: {key.hex()}")
    execute_faults(library)
    process_outputs(output_dir_from_key(library, key), clean)


# There is some additional work per faulted instruction. This is hard to
# quantify, the following constant is a guesstimate based on experiments.
# If the first chunks tend to end early, increase this number.
# If the last chunks tend to end early, decrease this number.
# The number represents how many simulated instructions is the work equal to.
ADDITIONAL_WORK_PER_INSTRUCTION = 180_000


def count_total_work(fault_range: range, total_checkpoints: int) -> int:
    range_size = len(fault_range)
    # Assume that the number of checkpoints has been optimized.
    # This means that their spacing corresponds to the equal amount
    # of simulated instructions.
    checkpoint_restore_work = range_size // total_checkpoints
    total_checkpoints_work = checkpoint_restore_work * range_size

    # How many instructions will have to be simulated from the fault to the end.
    # It is a sum of numbers from 1 to N, where N is the size of the range.
    total_after_fault_work = range_size * (range_size + 1) // 2
    # How many instructions will have to be simulated from the checkpoint to the fault.
    # Realize that the number of instructions from checkpoint to fault is between
    # 0 and checkpoint_restore_work, as that is how the number of checkpoints
    # should have been optimized.
    total_before_fault_work = (checkpoint_restore_work // 2) * range_size
    total_instructions_work = total_after_fault_work + total_before_fault_work

    total_additional_work = ADDITIONAL_WORK_PER_INSTRUCTION * range_size

    total_work = total_instructions_work + total_checkpoints_work + total_additional_work

    return total_work


def split_fault_range(fault_range: range, num_chunks: int, total_checkpoints: int) -> list[range]:
    """
    We explicitly define a split function because splitting the range evenly
    is far from optimal. The faults at the start take much longer to simulate,
    because faults at the end gain much more speedup from checkpoints.

    We use the total number of checkpoints to estimate how much time it takes
    to restore a checkpoint (the function assumes the number is already optimized
    for the fault range size).
    """
    range_size = len(fault_range)
    checkpoint_restore_work = range_size // total_checkpoints
    total_work = count_total_work(fault_range, total_checkpoints)
    work_per_chunk = total_work // num_chunks

    current_chunk_start = fault_range.start
    current_chunk_work = 0
    chunks: list[range] = []

    # Go through the instructions, accumulate the work, and create a new chunk
    # whenever the work exceeds the average work per chunk.
    for inst_num in fault_range:
        if len(chunks) == num_chunks - 1:
            # The last chunk has to go to the end.
            chunks.append(range(current_chunk_start, fault_range.stop))

            # Calculate the work of the final chunk for sanity check.
            last_chunk_work = sum(
                checkpoint_restore_work + checkpoint_restore_work // 2 +
                (range_size - (inst_num - fault_range.start)) + ADDITIONAL_WORK_PER_INSTRUCTION
                for inst_num in range(current_chunk_start, fault_range.stop)
            )
            last_chunk_work_percentage = (100 * last_chunk_work) // work_per_chunk
            print(f"Last chunk received {last_chunk_work_percentage}% of the average work (should be around 100%).")
            break

        # We do not know where was the last checkpoint so we always use the average.
        work_before = checkpoint_restore_work // 2
        work_after = range_size - (inst_num - fault_range.start)
        current_chunk_work += checkpoint_restore_work + work_before + work_after + ADDITIONAL_WORK_PER_INSTRUCTION
        if current_chunk_work >= work_per_chunk:
            chunks.append(range(current_chunk_start, inst_num))
            current_chunk_start = inst_num + 1
            current_chunk_work = 0

    return chunks


def simulate_faults_parallel(library: Library, optimal_threads: int | None = None) -> None:
    """
    In the entire function we do not care about the small inefficiencies that
    arise if the optimal threads does not divide the total number of cores,
    or if the last chunk is smaller/bigger than the others.
    """
    # If the optimal number of threads was passed, use that.
    # If not, try to read it from the environment variable FF_OPT_THREADS (FaultFinder optimal threads).
    # If the environment variable is not set, use 8 as a reasonable default.
    if optimal_threads is None:
        optimal_threads = int(os.getenv("FF_OPT_THREADS", "8"))

    # Assume 1 core if the number of cores cannot be determined.
    total_cores = os.cpu_count() or 1

    if not 1 <= optimal_threads <= total_cores:
        raise ValueError(f"optimal_threads must be between 1 and the number of available cores ({total_cores}).")

    num_chunks = total_cores // optimal_threads

    total_checkpoints = get_number_of_checkpoints(library)
    fault_range = get_fault_range(library)
    # If total_checkpoints is larger than the number of faulted instructions,
    # assume 1 instruction per checkpoint. This never happens "in production".
    inst_per_checkpoint = len(fault_range) // total_checkpoints or 1

    chunks = split_fault_range(fault_range, num_chunks, total_checkpoints)

    # Assume the public and private keys are already set in the jsons.
    key = get_private_key(library)
    # Number of threads only need to be set once.
    set_num_threads(library, optimal_threads)

    #
    # Spawn the parallel processes.
    #
    with Pool(num_chunks) as pool:
        for chunk_num, chunk_range in enumerate(chunks):
            # Different chunks might have different lengths so the number of checkpoints differs.
            # Avoid setting it to 0, FaultFinder will fail. "In production", this never happens.
            num_checkpoints = len(chunk_range) // inst_per_checkpoint or 1
            set_num_checkpoints(library, num_checkpoints)
            set_output_dir(library, key, str(chunk_num))
            set_fault_range(library, chunk_range)

            print(f"Starting chunk {chunk_num} for fault range {chunk_range}.")
            pool.apply_async(
                execute_faults, args=(library,),
                callback=lambda _, num=chunk_num: print(f"Chunk {num} done at {datetime.now()}.")
            )

            # Give the process time to start and read the config files from disk.
            sleep(10)

        pool.close()
        pool.join()

    #
    # Restore the original state.
    #
    set_num_checkpoints(library, total_checkpoints)
    set_fault_range(library, fault_range)
    set_output_dir(library, key)
    set_num_threads(library, total_cores)
