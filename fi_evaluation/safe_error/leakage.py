from abc import ABC, abstractmethod


class LeakageModel(ABC):
    @abstractmethod
    def complementary_key(self, original_key: bytes) -> bytes:
        """
        Generate a complementary key based on the original key.
        """


class KeyBits(LeakageModel):
    def complementary_key(self, original_key: bytes) -> bytes:
        """
        Generate a key that has the opposite bits to the original key.
        """
        return bytes(~b & 0xFF for b in original_key)


class NeighbouringBitsXor(LeakageModel):
    def complementary_key(self, original_key: bytes) -> bytes:
        """
        Generate a key for which the XOR of each pair of neighbouring bits
        is different than the XOR of the two bits on the same positions
        in the original key.
        Example:
        Original key:       00110011
        Complementary key:  10011001
        """
        bits_length = len(original_key) * 8
        original_key_int = int.from_bytes(original_key, "little")
        previous_bit_original = previous_bit_new = original_key_int & 1
        # We can choose the lowest bit freely, we choose it to be the same as
        # the original key's lowest bit.
        new_key_int = previous_bit_new
        for i in range(bits_length - 1):
            original_key_int >>= 1
            current_bit_original = original_key_int & 1
            original_xor = previous_bit_original ^ current_bit_original
            new_xor = 1 ^ original_xor
            current_bit_new = previous_bit_new ^ new_xor
            new_key_int |= current_bit_new << (i + 1)
            previous_bit_original = current_bit_original
            previous_bit_new = current_bit_new

        return new_key_int.to_bytes(len(original_key), "little")
