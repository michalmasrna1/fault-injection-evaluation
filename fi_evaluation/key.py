from abc import ABC, abstractmethod
from itertools import combinations
from typing import Iterable


class LowEntropyKeyGenerator(ABC):
    @abstractmethod
    def generate(self) -> Iterable[tuple[bytes, int]]:
        pass


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
    """
    Generate keys by shifting the original key any number of bits to the
    left or right, filling the remaining bits with the filler.
    Shift by 0 is skipped to avoid yielding the original key.
    The filler represents the data that is "around" the original key.
    It should be as long as the keys that will be generated.

    As we do not know whether the library interprets the key as big or little
    endian, we try both for the key and also for the filler.

    Example:
    Key: 01001101
    Filler: 10011001
    The full "view" would be 10011001|01001101|10011001
    Generated keys (what is between | |):
    10011001|01001101|10011001    -    10011001|01001101|10011001
    -------------------------------------------------------------
    00110010|10011011|0011001     1     1001100|10100110|11001100
    01100101|00110110|011001      2      100110|01010011|01100110
                ...               ...               ...
    01001101|10011001|            8            |10011001|01001101
    """

    def __init__(self, filler: bytes):
        self.filler = filler

    def generate(self, original_key: bytes) -> Iterable[tuple[bytes, int]]:
        if not len(original_key) == len(self.filler):
            raise ValueError(
                f"The key must be the same length as the filler."
                f" Filler length: {len(self.filler)}, key length: {len(original_key)}"
            )

        size_bits = len(original_key) * 8
        for key_endian in ['little', 'big']:
            for filler_endian in ['little', 'big']:
                # Assertions for typing purposes.
                assert key_endian == "big" or key_endian == "little"
                assert filler_endian == "big" or filler_endian == "little"

                original_key_int = int.from_bytes(original_key, byteorder=key_endian)
                filler_int = int.from_bytes(self.filler, byteorder=filler_endian)
                for shift in range(1, size_bits):
                    shifted_left = (original_key_int << shift) & ((1 << size_bits) - 1)
                    shifted_right = original_key_int >> shift
                    shifted_left_filled = shifted_left | (filler_int & ((1 << shift) - 1))
                    shifted_right_filled = shifted_right | (filler_int & (((1 << shift) - 1) << (size_bits - shift)))

                    entropy = size_bits - shift
                    yield shifted_left_filled.to_bytes(len(original_key), key_endian), entropy
                    yield shifted_right_filled.to_bytes(len(original_key), key_endian), entropy


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
            yield (unshifted_mask << (i * self.block_size_bits)).to_bytes(self.key_size_bits // 8, 'little')


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
def generate_low_entropy_keys(original_key: bytes) -> Iterable[tuple[bytes, int]]:
    """
    Returns tuples of (low_entropy_key, entropy), where the entropy
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

    # Shifted keys filled with 0s.
    yield from ShiftedKeyGenerator(b'\x00' * len(original_key)).generate(original_key)
    # Shifted keys filled with 1s.
    yield from ShiftedKeyGenerator(b'\xff' * len(original_key)).generate(original_key)

    yield from HighestLowestByteKeyGenerator().generate()


def generate_faulted_outputs(original_output: bytes, buffer_content: bytes) -> Iterable[tuple[bytes, int]]:
    """
    Returns tuples of (faulted_output, entropy), where the entropy
    represents how many bits were used from the original output.

    This should represent cases when the output copying loop was manipulated.
    Not all Generators are used as not all of them make sense as opposed to
    in generate_low_entropy_keys.

    The buffer_content represents the data that is in the output buffer
    at the beginning of the execution. For the thesis, this is probably:
    0xecc25519ecc25519ecc25519ecc25519ecc25519ecc25519ecc25519ecc25519
    """
    fault_masks: set[bytes] = set()  # A set because we only care about unique masks.
    output_size_bits = len(original_output) * 8

    for block_size_bits in [8, 32, 64, 128]:
        mask_generator = BlockMaskGenerator(block_size_bits, output_size_bits)
        fault_masks.update(mask_generator.generate())

    fault_masks.update(BeginningEndMaskGenerator(output_size_bits).generate())

    for mask in fault_masks:
        # This and that ^ has to be brought into one function.
        # The function accepts the mask, the original bytes and the "filler".
        num_bits = bin(int.from_bytes(mask, byteorder='little')).count('1')
        faulted_output_bytes = bytes(a & b for a, b in zip(original_output, mask))
        yield faulted_output_bytes, num_bits

    # Shifted output filled with 0s.
    yield from ShiftedKeyGenerator(b'\x00' * len(original_output)).generate(original_output)
    # Shifted output filled with 1s.
    yield from ShiftedKeyGenerator(b'\xff' * len(original_output)).generate(original_output)
    # Shifted output filled with the original buffer contents.
    yield from ShiftedKeyGenerator(buffer_content).generate(original_output)
