"""
Even though the thesis does not evaluate against the register zeroing fault,
it remains implemented, should anyone want to use it.
"""

import os
from enum import Enum
from typing import Iterable

NO_OUTPUT = b"nooutput" * 4  # 32 bytes placeholder representing no output


class FaultType(Enum):
    ZERO = 0  # Register zeroing
    SKIP = 1  # Instruction skip
    FLIP = 2  # Instruction bit flip


class FaultTarget(Enum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3
    R4 = 4
    R5 = 5
    R6 = 6
    R7 = 7
    R8 = 8
    SB = 9
    SL = 10
    FP = 11
    IP = 12
    SP = 13
    LR = 14
    PC = 15
    IR = 20


class Fault:
    fault_type: FaultType
    target: FaultTarget  # the faulted register, IR for instruction skips, PC for instruction bit flips
    mask: bytes  # The number of skipped instructions or the bit mask of affected bits
    old_value: bytes  # The old value of the faulted register
    new_value: bytes  # The new value of the faulted register

    def __init__(self, fault_type: FaultType, target: FaultTarget, mask: bytes, old_value: bytes, new_value: bytes):
        self.fault_type = fault_type
        self.target = target
        self.mask = mask
        self.old_value = old_value
        self.new_value = new_value

    def __str__(self) -> str:
        def format_instr(instruction: bytes) -> str:
            instruction_hex = instruction.hex()
            if instruction_hex.startswith("000000000000"):
                non_zero_part = instruction_hex[12:]
            if instruction_hex.startswith("00000000"):
                non_zero_part = instruction_hex[8:]
            else:
                non_zero_part = instruction_hex

            return " ".join(non_zero_part[i:i + 2] for i in range(0, len(non_zero_part), 2))

        if self.fault_type == FaultType.SKIP:
            return f"Skipped {self.mask_int} instruction{'s' if self.mask_int > 1 else ''}"

        if self.fault_type == FaultType.FLIP:
            return f"Flipped instruction bit ({format_instr(self.old_value)} -> {format_instr(self.new_value)})"

        if self.fault_type == FaultType.ZERO:
            return f"Zeroed register {self.target.name}"

        raise ValueError(f"Unknown fault type: {self.fault_type}")

    @property
    def mask_int(self) -> int:
        return int.from_bytes(self.mask)

    def to_bytes(self) -> bytes:
        if len(self.mask) > 4 or len(self.old_value) > 4 or len(self.new_value) > 4:
            raise ValueError("Mask, old value and new value must be at most 4 bytes long.")
        return (
            self.fault_type.value.to_bytes(2, "little")
            + self.target.value.to_bytes(2, "little")
            + self.mask.rjust(4, b"\x00")
            + self.old_value.rjust(4, b"\x00")
            + self.new_value.rjust(4, b"\x00")
        )

    @staticmethod
    def from_bytes(data: bytes) -> 'Fault':
        if len(data) != 16:
            raise ValueError("Fault data must be exactly 16 bytes long.")
        fault_type = FaultType(int.from_bytes(data[0:2], "little"))
        target = FaultTarget(int.from_bytes(data[2:4], "little"))
        mask = data[4:8]
        old_value = data[8:12]
        new_value = data[12:16]
        return Fault(fault_type, target, mask, old_value, new_value)


class ExecutedInstruction:
    instruction: int
    address: bytes
    hit: int

    def __init__(self, instruction: int, address: bytes, hit: int):
        self.instruction = instruction
        self.address = address
        self.hit = hit

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ExecutedInstruction):
            return False

        return (self.instruction == other.instruction and
                self.address == other.address and
                self.hit == other.hit)

    def to_bytes(self) -> bytes:
        if len(self.address) > 4 or self.hit > 2**32 or self.instruction > 2**32:
            raise ValueError("One of the fields is too long for the expected size.")
        return (
            self.instruction.to_bytes(4, "little")
            + self.address.rjust(4, b"\x00")
            + self.hit.to_bytes(4, "little")
        )

    @staticmethod
    def from_bytes(data: bytes) -> 'ExecutedInstruction':
        if len(data) != 12:
            raise ValueError("ExecutedInstruction data must be exactly 12 bytes long.")
        instruction = int.from_bytes(data[0:4], "little")
        address = data[4:8]
        hit = int.from_bytes(data[8:12], "little")
        return ExecutedInstruction(instruction, address, hit)


class SimulationResult:
    executed_instruction: ExecutedInstruction
    fault: Fault
    errored: bool
    output: bytes | None

    def __init__(self, executed_instruction: ExecutedInstruction, fault: Fault, errored: bool, output: bytes | None):
        self.executed_instruction = executed_instruction
        self.fault = fault
        self.errored = errored
        self.output = output

    def __str__(self) -> str:
        inst = self.executed_instruction
        return f"Address {inst.address.hex()} on hit {inst.hit} ({inst.instruction}) - {self.fault}"

    def to_bytes(self) -> bytes:
        # If there was no output we save the special value NO_OUTPUT
        # so that the record is still 64 bytes long.
        output = self.output if self.output is not None else NO_OUTPUT
        if len(output) != 32:
            raise ValueError("The output has to be 32 bytes long.")
        return (
            self.executed_instruction.to_bytes()  # 12 bytes
            + self.fault.to_bytes()  # 16 bytes
            + self.errored.to_bytes(4, "little")
            + output
        )

    @staticmethod
    def from_bytes(data: bytes) -> 'SimulationResult':
        if len(data) != 64:
            raise ValueError("SimulationResult data must be exactly 64 bytes long.")
        executed_instruction = ExecutedInstruction.from_bytes(data[0:12])
        fault = Fault.from_bytes(data[12:28])
        errored = bool.from_bytes(data[28:32])
        output = None if data[32:64] == NO_OUTPUT else data[32:64]
        return SimulationResult(executed_instruction, fault, errored, output)


def print_sorted_simulation_results(results: set[SimulationResult]):
    """
    Print a set of simulation results in a sorted order.
    """
    for result in sorted(results, key=lambda r: r.executed_instruction.instruction):
        print(result)


def read_processed_outputs(output_dir: str, skip_errors: bool) -> Iterable[SimulationResult]:
    for filename in os.listdir(output_dir):
        if filename.endswith(".bin"):
            with open(os.path.join(output_dir, filename), "rb") as output_file:
                # Read 64 byte chunks, for each call SimulationResult.from_bytes()
                while chunk := output_file.read(64):
                    result = SimulationResult.from_bytes(chunk)

                    if skip_errors and (result.errored or result.output == NO_OUTPUT):
                        # There was no output, we skip the result
                        continue

                    yield result


def load_ordered_sim_results(
        output_dir: str, skip_errors: bool) -> list[dict[tuple[FaultType, FaultTarget], SimulationResult]]:
    results_ordered: list[dict[tuple[FaultType, FaultTarget], SimulationResult]] = []

    for result_sim in read_processed_outputs(output_dir, skip_errors=skip_errors):
        instruction_number = result_sim.executed_instruction.instruction

        # Ensure the list is large enough
        if len(results_ordered) <= instruction_number:
            results_ordered.extend([{} for _ in range(instruction_number - len(results_ordered) + 1)])

        fault = result_sim.fault

        # We should not fault the same instruction in the same way more than once.
        assert (fault.fault_type, fault.target) not in results_ordered[instruction_number]

        results_ordered[instruction_number][(fault.fault_type, fault.target)] = result_sim

    return results_ordered
