import json
import os
from itertools import combinations
from typing import Iterable, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from pyecsca.ec.context import DefaultContext, Node, ResultAction, local
from pyecsca.ec.formula import LadderFormula, ScalingFormula
from pyecsca.ec.mult import LadderMultiplier
from pyecsca.ec.params import get_params
from pyecsca.ec.point import Point
from results import SimulationResult

EXECUTABLE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_public_key_bytes_from_private_bytes(private_bytes: bytes) -> bytes:
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding(serialization.Encoding.Raw),
        format=serialization.PublicFormat(serialization.PublicFormat.Raw))
    return public_key_bytes


def swap_endian(key: bytes) -> bytes:
    # Swap the endianness of the key
    swapped_key = int.from_bytes(key, byteorder='big')
    swapped_key = swapped_key.to_bytes(32, byteorder='little')
    return swapped_key


def parse_output(output_dir: str) -> Iterable[SimulationResult]:
    for filename in os.listdir(output_dir):
        if filename.endswith(".bin"):
            with open(os.path.join(output_dir, filename), "rb") as output_file:
                # Read 64 byte chunks, for each call SimulationResult.from_bytes()
               while chunk := output_file.read(64):
                   yield SimulationResult.from_bytes(chunk)


def generate_computational_loop_abort_keys():
    curve25519 = get_params("other", "Curve25519", "xz", infty=False)
    ladd = curve25519.curve.coordinate_model.formulas["ladd-1987-m-3"]
    scl = curve25519.curve.coordinate_model.formulas["scale"]
    assert isinstance(ladd, LadderFormula)
    assert isinstance(scl, ScalingFormula)

    multiplier = LadderMultiplier(ladd, scl=scl, complete=False, short_circuit=False, full=True)
    generator = curve25519.generator
    key = bytes([0x80, 0x65, 0x74, 0xba, 0x61, 0x62, 0xcd, 0x58, 0x49, 0x30, 0x59, 0x47,
                0x36, 0x16, 0x35, 0xb6, 0xe7, 0x7d, 0x7c, 0x7a, 0x83, 0xde, 0x38, 0xc0,
                0x80, 0x74, 0xb8, 0xc9, 0x8f, 0xd4, 0x0a, 0x43])

    with local(DefaultContext()) as ctx:
        assert isinstance(ctx, DefaultContext)
        multiplier.init(curve25519, generator)
        multiplier.multiply(int.from_bytes(key, byteorder="little"))

        multiplication_node = ctx.actions[0]
        for bit_no, child in enumerate(multiplication_node.children):
            assert isinstance(child, Node)
            assert isinstance(child.action, ResultAction)
            action = child.action
            result_point: Point | None = None
            if len(action.result) == 2:
                # One of the ladder steps, the two results are xp and xq
                # The correct result is determined by the last processed bit
                # (see the last call to cswap after the computational loop)
                correct_index = int.from_bytes(key, "little") >> (254 - bit_no) & 1
                # reduce and pack the result
                result_point = multiplier._scl(action.result[correct_index])
            elif len(action.result) == 1:
                # The final result after the reduction (packing, scaling)
                result_point = action.result[0]
            else:
                raise ValueError(f"Unexpected result length: {len(action.result)}")
            assert isinstance(result_point, Point) # result_point is not None
            print(int(str(result_point.coords["X"])).to_bytes(32, byteorder="little").hex())


def generate_faulted_keys(original_key: bytes) -> Iterable[bytes]:
    fault_masks: list[bytes] = []
    # Keep every of the 1, 4, 8 and 16 bytes blocks.
    for block in [8, 32, 64, 128]:
        unshifted_mask: int = 2**block - 1
        fault_masks.extend([(unshifted_mask << (i * block)).to_bytes(32, 'big') for i in range(256 // block)])

    # Any number of bits from the start + any number of bits from the end
    # There is some overlap with the first loop, but we do not care
    for bits_from_start in range(0, 256):
        # Leave a space of at least one faulted bit, otherwise you use the full key
        for bits_from_end in range(0, 256 - bits_from_start):
            if bits_from_start + bits_from_end == 0:
                continue
            start_of_mask = ((1 << 256) - 1) ^ (1 << 256 - bits_from_start) - 1
            end_of_mask = (1 << bits_from_end) - 1
            fault_masks.append((start_of_mask | end_of_mask).to_bytes(32, 'big'))
            fault_masks.append((start_of_mask | end_of_mask).to_bytes(32, 'little'))

    for mask in fault_masks:
        faulted_key_bytes = bytes(a & b for a, b in zip(original_key, mask))
        yield faulted_key_bytes

    # The original key shifted any number of positions to either left or right,
    # the remaining bits set to either 0 or 1
    for bits_shifted in range(1, 256):
        endian: Literal['big'] | Literal['little']
        for endian in ['big', 'little']:
            # for endian in ['little']:
            # The shifts with big are not really what we want as the keys are interpreted as low endian
            # but we keep them just in case \_()_/
            shifted_left_fill_0 = (int.from_bytes(original_key, byteorder=endian) << bits_shifted) & ((1 << 256) - 1)
            shifted_right_fill_0 = int.from_bytes(original_key, byteorder=endian) >> bits_shifted
            shifted_left_fill_1 = shifted_left_fill_0 | ((1 << bits_shifted) - 1)
            shifted_right_fill_1 = shifted_right_fill_0 | (((1 << bits_shifted) - 1) << (256 - bits_shifted))
            yield from (x.to_bytes(32, endian) for x in (
                shifted_left_fill_0,
                shifted_right_fill_0,
                shifted_left_fill_1,
                shifted_right_fill_1
            ))

    for i in range(1 << 8):
        yield i.to_bytes(32, 'big')
        yield i.to_bytes(32, 'little')

    # Only highest and lowest byte non-empty
    for upper_num_bits in range(0, 8):
        for upper_bits in combinations(range(8), upper_num_bits):
            for lower_num_bits in range(0, 8):
                for lower_bits in combinations(range(8), lower_num_bits):
                    faulted_key = 0
                    for bit in upper_bits:
                        faulted_key |= 1 << bit
                    for bit in lower_bits:
                        faulted_key |= 1 << (bit + 248)
                    yield faulted_key.to_bytes(32, 'big')  # endianity doesn't really matter here


def generate_faulted_results(original_key: bytes) -> Iterable[tuple[bytes, bytes]]:
    key_result_dict: dict[str, str] = {}
    faulted_results_path = os.path.join(EXECUTABLE_DIR, "faulted_results.json")
    if os.path.exists(faulted_results_path):
        with open(faulted_results_path) as f:
            key_result_dict = json.loads(f.read())
    for faulted_key in generate_faulted_keys(original_key):
        clamped_key = clamp(faulted_key)
        if clamped_key.hex() in key_result_dict:
            resulting_public_key = bytes.fromhex(key_result_dict[clamped_key.hex()])
        else:
            resulting_public_key = get_public_key_bytes_from_private_bytes(clamped_key)
            key_result_dict[clamped_key.hex()] = resulting_public_key.hex()
        yield clamped_key, resulting_public_key
    with open(faulted_results_path, 'w') as f:
        f.write(json.dumps(key_result_dict))


def clamp(key: bytes) -> bytes:
    key_int = int.from_bytes(key, byteorder='little')
    key_int &= ~(1 << 255)  # highest bit is 0
    key_int |= (1 << 254)  # second highest bit is 1
    key_int &= ~7  # lowest three bits are 0
    return key_int.to_bytes(32, 'little')


def check_key_shortening(output_dir: str):
    results_sim: dict[bytes, dict[bytes, set[int]]] = {}
    for result_sim in parse_output(output_dir):
        if result_sim.output not in results_sim:
            results_sim[result_sim.output] = {}
        if result_sim.executed_instruction.address not in results_sim[result_sim.output]:
            results_sim[result_sim.output][result_sim.executed_instruction.address] = set()
        results_sim[result_sim.output][result_sim.executed_instruction.address].add(result_sim.executed_instruction.hit)

    seen_effective_keys: dict[bytes, dict[bytes, set[int]]] = {}
    untouched_key = bytes([0x80, 0x65, 0x74, 0xba, 0x61, 0x62, 0xcd, 0x58, 0x49, 0x30, 0x59, 0x47,
                           0x36, 0x16, 0x35, 0xb6, 0xe7, 0x7d, 0x7c, 0x7a, 0x83, 0xde, 0x38, 0xc0,
                           0x80, 0x74, 0xb8, 0xc9, 0x8f, 0xd4, 0x0a, 0x43])
    for faulted_key, result in generate_faulted_results(untouched_key):
        if result in results_sim:
            if faulted_key in seen_effective_keys:
                continue
            seen_effective_keys[faulted_key] = results_sim[result]

    # Order by how many bits are removed from the untouched key
    # TODO: The sort does not work correctly with the shifted keys
    for faulted_key, addresses in sorted(
        seen_effective_keys.items(),
        key=lambda item: bin(int.from_bytes(item[0], byteorder='big') ^
                             int.from_bytes(untouched_key, byteorder='big')).count('1'),
        reverse=True
    ):
        print(f"Faulted key - {faulted_key.hex()}.")
        for address, hits in addresses.items():
            print(f"Address {address.hex()} on hits {', '.join(map(str, sorted(hits)))}")
        print()


def check_known_outputs(output_dir: str):
    known_outputs_path = os.path.join(EXECUTABLE_DIR, "known_outputs.txt")
    with open(known_outputs_path, "r") as f:
        known_outputs = [bytes.fromhex(line) for line in f.read().splitlines()]
    known_outputs = set(known_outputs)
    seen_known_outputs: dict[bytes, dict[bytes, set[int]]] = {}
    # TODO: parse the output only once when checking predictable outputs
    # - you are also parsing the output in check_key_shortening
    for result_sim in parse_output(output_dir):
        output = result_sim.output
        if output in known_outputs:
            if output not in seen_known_outputs:
                seen_known_outputs[output] = {result_sim.executed_instruction.address: set([result_sim.executed_instruction.hit])}
            else:
                if result_sim.executed_instruction.address in seen_known_outputs[output]:
                    seen_known_outputs[output][result_sim.executed_instruction.address].add(result_sim.executed_instruction.hit)
                else:
                    seen_known_outputs[output][result_sim.executed_instruction.address] = set([result_sim.executed_instruction.hit])

    for output, addresses in seen_known_outputs.items():
        print(f"Known output discovered - {output.hex()}")
        for address, hits in addresses.items():
            print(f"Address {address.hex()} on hits {', '.join(map(str, sorted(hits)))}")


def check_predictable_outputs(output_dir: str):
    check_key_shortening(output_dir)
    check_known_outputs(output_dir)


def check_safe_error(output_dir_1: str, output_dir_2: str):
    results_sim_1 = list(parse_output(output_dir_1))
    results_sim_2 = list(parse_output(output_dir_2))
    print(f"Number of fault results: {len(results_sim_1)}, {len(results_sim_2)}")
    print()
    # Any value definitely larger than the total number of instructions
    results_sim_1_ordered: list[SimulationResult | None] = [None for _ in range(1_000_000)]
    results_sim_2_ordered: list[SimulationResult | None] = [None for _ in range(1_000_000)]
    for result_sim_1_tmp in results_sim_1:
        results_sim_1_ordered[result_sim_1_tmp.executed_instruction.instruction] = result_sim_1_tmp
    for result_sim_2_tmp in results_sim_2:
        results_sim_2_ordered[result_sim_2_tmp.executed_instruction.instruction] = result_sim_2_tmp
    # # All zeroes
    # correct_result_1 = get_public_key_bytes_from_private_bytes(int(0).to_bytes(32, 'big'))
    # # All ones
    # correct_result_2 = get_public_key_bytes_from_private_bytes(int((1 << 256) - 1).to_bytes(32, 'big'))
    # All 0x93
    correct_result_1 = get_public_key_bytes_from_private_bytes(bytes([0x93] * 32))
    # All 0x6c
    correct_result_2 = get_public_key_bytes_from_private_bytes(bytes([0x6c] * 32))

    potentially_prone_addresses: dict[bytes, set[int]] = {}
    for result_sim_1, result_sim_2 in zip(
            results_sim_1_ordered, results_sim_2_ordered):
        if result_sim_1 is None or result_sim_2 is None:
            continue
        assert result_sim_1.executed_instruction.address == result_sim_2.executed_instruction.address
        assert result_sim_1.executed_instruction.hit == result_sim_2.executed_instruction.hit
        assert result_sim_1.executed_instruction.instruction == result_sim_2.executed_instruction.instruction

        if (result_sim_1.output == correct_result_1) ^ (result_sim_2.output == correct_result_2):
            if result_sim_1.executed_instruction.address not in potentially_prone_addresses:
                potentially_prone_addresses[result_sim_1.executed_instruction.address] = set()
            potentially_prone_addresses[result_sim_1.executed_instruction.address].add(result_sim_1.executed_instruction.hit)

    print("Addresses potentially prone to safe error attack:")
    for address, hits in sorted(potentially_prone_addresses.items()):
        print(f"{address.hex()} on hits ({', '.join(map(str, sorted(hits)))})")


def main():
    results_dir = os.path.join(EXECUTABLE_DIR, "sca25519-static", "outputs", "original-skips-only")
    check_predictable_outputs(results_dir)

    # output_dir_1 = os.path.join(executable_dir, "sca25519-unprotected", "outputs-93")
    # output_dir_2 = os.path.join(executable_dir, "sca25519-unprotected", "outputs-6c")
    # check_safe_error(output_dir_1, output_dir_2)


main()
