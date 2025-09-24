from leakage import KeyBits, NeighbouringBitsXor, SafeErrorModel


def safe_error_model_from_name(name: str) -> SafeErrorModel:
    if name == "key-bits":
        return KeyBits()
    if name == "neighbouring-bits-xor":
        return NeighbouringBitsXor()
    raise ValueError(f"Unknown safe error model: {name}. Known models are:\n- key-bits\n- neighbouring-bits-xor")
