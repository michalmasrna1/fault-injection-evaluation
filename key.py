from abc import ABC, abstractmethod
from itertools import combinations
from typing import Iterable


class LowEntropyKeyGenerator(ABC):
    @abstractmethod
    def generate(self) -> Iterable[tuple[bytes, int]]:
        pass


class SmallNumberKeyGenerator(LowEntropyKeyGenerator):
    def generate(self) -> Iterable[tuple[bytes, int]]:
        """
        Generate keys representing small numbers in small and big endian.
        """
        for i in range(1 << 8):
            num_bits = bin(i).count('1')
            yield i.to_bytes(32, 'big'), num_bits
            yield i.to_bytes(32, 'little'), num_bits


class HighestLowestByteKeyGenerator(LowEntropyKeyGenerator):
    def generate(self) -> Iterable[tuple[bytes, int]]:
        """
        Generate keys with bits only set in the highest and the lowest byte.
        """
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


class FaultedKeyGenerator(ABC):
    @abstractmethod
    def generate(self, original_key: bytes) -> Iterable[tuple[bytes, int]]:
        pass


class ShiftedKeyGenerator(FaultedKeyGenerator):
    def generate(self, original_key: bytes) -> Iterable[tuple[bytes, int]]:
        """
        Generate keys by shifting the original key any number of bits to the
        left or right, filling the remaining bits with either 0 or 1.
        """
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


class MaskGenerator(ABC):
    @abstractmethod
    def generate(self) -> Iterable[bytes]:
        """
        Generate masks that can be applied to the original key.
        The original key will retain the bits corresponding to
        the bits of the mask set to 1.
        The entropy of the mask is always the number of 1s,
        so it does not have to be calculated here.
        """


class BlockMaskGenerator(MaskGenerator):
    def __init__(self, block_size_bits: int, key_size_bits: int):
        self.block_size_bits = block_size_bits
        self.key_size_bits = key_size_bits

    def generate(self) -> Iterable[bytes]:
        """
        Generate masks representing `block_size` consecutive ones
        shifted through the key. From block_size 16 and key size 64
        bytes, this would be:
        0x000000000000ffff
        0x00000000ffff0000
        0x0000ffff00000000
        0xffff000000000000
        """
        unshifted_mask: int = 2**self.block_size_bits - 1
        for i in range(self.key_size_bits // self.block_size_bits):
            yield (unshifted_mask << (i * self.block_size_bits)).to_bytes(32, 'little')


class BeginningEndMaskGenerator(MaskGenerator):
    def __init__(self, key_size_bits: int):
        self.key_size_bits = key_size_bits

    def generate(self) -> Iterable[bytes]:
        # Any number of bits from the start + any number of bits from the end
        for bits_from_start in range(0, self.key_size_bits):
            # Leave a space of at least one faulted bit, otherwise you use the full key
            for bits_from_end in range(0, self.key_size_bits - bits_from_start):
                if bits_from_start + bits_from_end == 0:
                    continue
                start_of_mask = ((1 << self.key_size_bits) - 1) ^ (1 << self.key_size_bits - bits_from_start) - 1
                end_of_mask = (1 << bits_from_end) - 1
                yield (start_of_mask | end_of_mask).to_bytes(32, 'big')
                yield (start_of_mask | end_of_mask).to_bytes(32, 'little')


# Which classes of faulted keys we want might be dependant on the library,
# but perhaps they can all use all of them by default.
# This should also be renamed as it generates also low entropy keys
# not connected to the original key.
def generate_faulted_keys(original_key: bytes) -> Iterable[tuple[bytes, int]]:
    """
    Returns tuples of (faulted_key, entropy), where the entropy
    represents how many bits were used from the original key.
    """
    fault_masks: set[bytes] = set()  # A set because we only care about unique masks.
    key_size_bits = len(original_key) * 8

    for block_size_bits in [8, 32, 64, 128]:
        mask_generator = BlockMaskGenerator(block_size_bits, key_size_bits)
        fault_masks.update(mask_generator.generate())

    fault_masks.update(BeginningEndMaskGenerator(key_size_bits).generate())

    for mask in fault_masks:
        num_bits = bin(int.from_bytes(mask, byteorder='little')).count('1')
        faulted_key_bytes = bytes(a & b for a, b in zip(original_key, mask))
        yield faulted_key_bytes, num_bits

    yield from ShiftedKeyGenerator().generate(original_key)

    yield from SmallNumberKeyGenerator().generate()

    yield from HighestLowestByteKeyGenerator().generate()
