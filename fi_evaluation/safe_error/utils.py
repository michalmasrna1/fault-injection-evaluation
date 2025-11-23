from fi_evaluation.safe_error.leakage import SafeErrorModel

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
NUM_BITS = 256
M = 1 << NUM_BITS


def regularize_k(k: int) -> int:
    # Ok to use the simplified implementation.
    return (k + N) % M


def unregularized_from_regularized(rk: int) -> int:
    unregularized = rk + M - N
    assert unregularized < M
    return unregularized


def secp256k1_complementary_key(model: SafeErrorModel, original_key: bytes) -> bytes:
    regularized_key = regularize_k(int.from_bytes(original_key, 'big'))
    complementary_key_bytes = model.complementary_key(regularized_key.to_bytes(32, 'big'), 'big')
    complementary_key_int = int.from_bytes(complementary_key_bytes, 'big')
    desired_key = unregularized_from_regularized(complementary_key_int)
    return desired_key.to_bytes(32, 'big')
