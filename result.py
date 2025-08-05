"""
Even though the thesis does not evaluate against the register zeroing fault,
it remains implemented, should anyone want to use it.
"""

import os
from enum import Enum
from typing import Iterable

NO_OUTPUT = b"nooutput" * 4  # 32 bytes placeholder representing no output

class FaultType(Enum):
    SKIP = 0  # Instruction skip
    FLIP = 1  # Instruction bit flip
    ZERO = 2  # Register zeroing


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
    target: FaultTarget  # the faulted register, IP for instruction skips, PC for instruction bit flips
    old_value: bytes  # The old value of the faulted register
    new_value: bytes  # The new value of the faulted register

    def __init__(self, fault_type: FaultType, target: FaultTarget, old_value: bytes, new_value: bytes):
        self.fault_type = fault_type
        self.target = target
        self.old_value = old_value
        self.new_value = new_value


    def __str__(self) -> str:
        def format_instruction(instruction: bytes) -> str:
            instruction_hex = instruction.hex()
            if instruction_hex.startswith("000000000000"):
                non_zero_part = instruction_hex[12:]
            if instruction_hex.startswith("00000000"):
                non_zero_part = instruction_hex[8:]
            else:
                non_zero_part = instruction_hex
            
            return " ".join(non_zero_part[i:i+2] for i in range(0, len(non_zero_part), 2))
             

        if self.fault_type == FaultType.SKIP:
            return f"Skipped instruction"
        elif self.fault_type == FaultType.FLIP:
            return f"Flipped instruction bit ({format_instruction(self.old_value)} -> {format_instruction(self.new_value)})"
        elif self.fault_type == FaultType.ZERO:
            return f"Zeroed register {self.target.name}"
        else:
            raise ValueError(f"Unknown fault type: {self.fault_type}")

    def to_bytes(self) -> bytes:
        if len(self.old_value) > 8 or len(self.new_value) > 8:
            raise ValueError("Old and new values must be at most 8 bytes long.")
        return (
            self.fault_type.value.to_bytes(1, "little")
            + self.target.value.to_bytes(1, "little")
            + self.old_value.rjust(8, b"\x00")
            + self.new_value.rjust(8, b"\x00")
        )

    @staticmethod
    def from_bytes(data: bytes) -> 'Fault':
        if len(data) != 18:
            raise ValueError("Fault data must be exactly 18 bytes long.")
        fault_type = FaultType(int.from_bytes(data[0:1], "little"))
        target = FaultTarget(int.from_bytes(data[1:2], "little"))
        old_value = data[2:10]
        new_value = data[10:18]
        return Fault(fault_type, target, old_value, new_value)


class ExecutedInstruction:
    instruction: int
    address: bytes
    hit: int

    def __init__(self, instruction: int, address: bytes, hit: int):
        self.instruction = instruction
        self.address = address
        self.hit = hit

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
        return f"Address {self.executed_instruction.address.hex()} on hit {self.executed_instruction.hit} ({self.executed_instruction.instruction}) - {self.fault}"

    def to_bytes(self) -> bytes:
        # If there was no output we save the special value NO_OUTPUT
        # so that the record is still 64 bytes long.
        output = self.output if self.output is not None else NO_OUTPUT
        if len(output) != 32:
            raise ValueError("The output has to be 32 bytes long.")
        return (
            self.executed_instruction.to_bytes()
            + self.fault.to_bytes()
            + self.errored.to_bytes(2, "little")
            + output
        )
    
    @staticmethod
    def from_bytes(data: bytes) -> 'SimulationResult':
        if len(data) != 64:
            raise ValueError("SimulationResult data must be exactly 64 bytes long.")
        executed_instruction = ExecutedInstruction.from_bytes(data[0:12])
        fault = Fault.from_bytes(data[12:30])
        errored = bool.from_bytes(data[30:32])
        output = None if data[32:64] == NO_OUTPUT else data[32:64]
        return SimulationResult(executed_instruction, fault, errored, output)
    

def print_sorted_simulation_results(results: set[SimulationResult]):
    """
    Print a set of simulation results in a sorted order.
    """
    sorted_results = sorted(results, key=lambda r: (r.executed_instruction.instruction, r.executed_instruction.hit))
    
    for result in sorted_results:
        print(result)


def read_processed_outputs(output_dir: str) -> Iterable[SimulationResult]:
    for filename in os.listdir(output_dir):
        if filename.endswith(".bin"):
            with open(os.path.join(output_dir, filename), "rb") as output_file:
                # Read 64 byte chunks, for each call SimulationResult.from_bytes()
               while chunk := output_file.read(64):
                    result = SimulationResult.from_bytes(chunk)

                    # TODO: Decide on how exactly to handle errors.
                    # It is possible that we do not want to see them when evaluating predictable outputs,
                    # but do want to see them when evaluating safe error.
                    if result.errored or result.output == NO_OUTPUT:
                       # There was no output, we skip the result
                       continue

                    yield result


# Also should probably be defined in some common IO file
def parse_known_outputs(known_outputs_path: str) -> dict[bytes, int]:
    known_outputs: dict[bytes, int] = {}

    with open(known_outputs_path, "r") as f:
        for line in f.read().splitlines():
            output_str, entropy_str = line.split(",")
            known_outputs[bytes.fromhex(output_str)] = int(entropy_str)

    return known_outputs
        