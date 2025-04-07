import os
import re
from typing import Iterable
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


class SimulationResult:
    address: str
    hit: int
    instruction: int
    result: str
    output: str

    def __init__(self, address: str, hit: int, instruction: int, result: str, output: str):
        self.address = address
        self.hit = hit
        self.instruction = instruction
        self.result = result
        self.output = output


def parse_output(output_dir: str) -> Iterable[SimulationResult]:
    output = ""
    for filename in os.listdir(output_dir):
        if filename.endswith(".txt"):
            with open(os.path.join(output_dir, filename), encoding="utf-8") as output_file:
                output += output_file.read()

    parsed = re.findall(r'#####.+?Address: (0x[a-f0-9]+?)\. Hit: (\d+).+?Instruction: (\d+).+?Run result: (.+?)$.+?Output.+?: ([a-f0-9]+?)$',
                        output, re.MULTILINE | re.DOTALL)
    for case in parsed:
        address, hit, instruction, result, output = case
        yield SimulationResult(
            address=address,
            hit=int(hit),
            instruction=int(instruction),
            result=result,
            output=output
        )


def get_public_key_bytes_from_private_bytes(private_bytes: bytes) -> bytes:
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding(serialization.Encoding.Raw),
        format=serialization.PublicFormat(serialization.PublicFormat.Raw))
    return public_key_bytes
    

def generate_faulted_results(original_key: bytes) -> Iterable[tuple[bytes, bytes]]:
    fault_masks: list[bytes] = []
    # Keep every of the 1, 4, 8 and 16 bytes blocks.
    for block in [8, 32, 64, 128]:
        unshifted_mask = 2**block - 1
        fault_masks.extend([
            (unshifted_mask << (i * block)).to_bytes(32, 'big') for i in range(256 // block)
        ])
        
    for mask in fault_masks:
        faulted_key_bytes = bytes(a & b for a, b in zip(original_key, mask))
        public_key_bytes = get_public_key_bytes_from_private_bytes(faulted_key_bytes)
        yield faulted_key_bytes, public_key_bytes


def check_key_shortening(output_dir: str):
    results_from_simulator = list(parse_output(output_dir))
    print(f"Number of fault results: {len(results_from_simulator)}")
    print()
    for faulted_key, result in generate_faulted_results(
        bytes([0x80, 0x65, 0x74, 0xba, 0x61, 0x62, 0xcd, 0x58, 0x49, 0x30, 0x59,
                0x47, 0x36, 0x16, 0x35, 0xb6, 0xe7, 0x7d, 0x7c, 0x7a, 0x83, 0xde,
                0x38, 0xc0, 0x80, 0x74, 0xb8, 0xc9, 0x8f, 0xd4, 0x0a, 0x43])):
        for result_from_simulator in results_from_simulator:
            if result_from_simulator.output == result.hex():
                print(f"Skipped address {result_from_simulator.address} on hit {result_from_simulator.hit}.")
                print(f"Resulting key - {faulted_key.hex()}.")
                print(f"Result - {result_from_simulator.output} ==")
                print(f"         {result.hex()}.")


def main():
    executable_dir = os.path.dirname(os.path.abspath(__file__))
    original_output_dir = os.path.join(executable_dir, "sca25519-unprotected", "outputs-original")
    check_key_shortening(original_output_dir)


main()
