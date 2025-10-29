from fi_evaluation.safe_error.evaluate import (evaluate_safe_error,
                                               print_safe_error_results)
from fi_evaluation.safe_error.leakage import (KeyBits, NeighbouringBitsXor,
                                              SafeErrorModel)


def safe_error_model_from_name(name: str) -> SafeErrorModel:
    if name == "key-bits":
        return KeyBits()
    if name == "neighbouring-bits-xor":
        return NeighbouringBitsXor()
    raise ValueError(f"Unknown safe error model: {name}. Known models are:\n- key-bits\n- neighbouring-bits-xor")
