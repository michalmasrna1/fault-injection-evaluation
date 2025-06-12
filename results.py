from enum import Enum


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
    D0 = 10
    PC = 20
    IP = 30


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

    def to_bytes(self) -> bytes:
        if len(self.old_value) > 8 or len(self.new_value) > 8:
            raise ValueError("Old and new values must be at most 8 bytes long.")
        return (
            self.fault_type.value.to_bytes(2, "little")
            + self.target.value.to_bytes(2, "little")
            + self.old_value.rjust(8, b"\x00")
            + self.new_value.rjust(8, b"\x00")
        )

    @staticmethod
    def from_bytes(data: bytes) -> 'Fault':
        if len(data) != 20:
            raise ValueError("Fault data must be exactly 20 bytes long.")
        fault_type = FaultType(int.from_bytes(data[0:2], "little"))
        target = FaultTarget(int.from_bytes(data[2:4], "little"))
        old_value = data[4:12]
        new_value = data[12:20]
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
    output: bytes

    def __init__(self, executed_instruction: ExecutedInstruction, fault: Fault, output: bytes):
        self.executed_instruction = executed_instruction
        self.fault = fault
        self.output = output

    def to_bytes(self) -> bytes:
        # Padding so that the record is of constant size (64 bytes),
        # so no delimiters are needed. We also check that
        # the fields are not longer than the expected size.
        if len(self.output) > 32:
            raise ValueError("One of the fields is too long for the expected size.")
        return (
            self.executed_instruction.to_bytes()
            + self.fault.to_bytes()
            + self.output.rjust(32, b"\x00")
        )
    
    @staticmethod
    def from_bytes(data: bytes) -> 'SimulationResult':
        if len(data) != 64:
            raise ValueError("SimulationResult data must be exactly 64 bytes long.")
        executed_instruction = ExecutedInstruction.from_bytes(data[0:12])
        fault = Fault.from_bytes(data[12:32])
        output = data[32:64]
        return SimulationResult(executed_instruction, fault, output)