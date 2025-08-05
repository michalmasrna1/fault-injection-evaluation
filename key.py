from itertools import combinations
from typing import Iterable


# This should definitely be split into multiple methods.
# Which classes of faulted keys we want might be dependant on the library,
# but perhaps they can all use all of them by default.
# This should also be renamed as it generates also low entropy keys
# not connected to the original key.
def generate_faulted_keys(original_key: bytes) -> Iterable[tuple[bytes, int]]:
    """
    Returns tuples of (faulted_key, entropy), where the entropy
    represents how many bits were used from the original key.
    """
    # A set because we only care about unique masks.
    fault_masks: set[bytes] = set()
    # Keep every of the 1, 4, 8 and 16 bytes blocks.
    for block in [8, 32, 64, 128]:
        unshifted_mask: int = 2**block - 1
        fault_masks.update((unshifted_mask << (i * block)).to_bytes(32, 'little') for i in range(256 // block))

    # Any number of bits from the start + any number of bits from the end
    for bits_from_start in range(0, 256):
        # Leave a space of at least one faulted bit, otherwise you use the full key
        for bits_from_end in range(0, 256 - bits_from_start):
            if bits_from_start + bits_from_end == 0:
                continue
            start_of_mask = ((1 << 256) - 1) ^ (1 << 256 - bits_from_start) - 1
            end_of_mask = (1 << bits_from_end) - 1
            fault_masks.add((start_of_mask | end_of_mask).to_bytes(32, 'big'))
            fault_masks.add((start_of_mask | end_of_mask).to_bytes(32, 'little'))

    for mask in fault_masks:
        num_bits = bin(int.from_bytes(mask, byteorder='little')).count('1')
        faulted_key_bytes = bytes(a & b for a, b in zip(original_key, mask))
        yield faulted_key_bytes, num_bits

    # The original key shifted any number of positions to either left or right,
    # the remaining bits set to either 0 or 1
    for bits_shifted in range(1, 256):
        shifted_left_fill_0 = (int.from_bytes(original_key, byteorder='little') << bits_shifted) & ((1 << 256) - 1)
        shifted_right_fill_0 = int.from_bytes(original_key, byteorder='little') >> bits_shifted
        shifted_left_fill_1 = shifted_left_fill_0 | ((1 << bits_shifted) - 1)
        shifted_right_fill_1 = shifted_right_fill_0 | (((1 << bits_shifted) - 1) << (256 - bits_shifted))
        yield from ((x.to_bytes(32, 'little'), 256 - bits_shifted) for x in (
            shifted_left_fill_0,
            shifted_right_fill_0,
            shifted_left_fill_1,
            shifted_right_fill_1
        ))

    for i in range(1 << 8):
        num_bits = bin(i).count('1')
        yield i.to_bytes(32, 'big'), num_bits
        yield i.to_bytes(32, 'little'), num_bits

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
                    yield faulted_key.to_bytes(32, 'little'), upper_num_bits + lower_num_bits

