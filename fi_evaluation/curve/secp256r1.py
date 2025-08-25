from fi_evaluation.curve import Curve


class SECP256R1(Curve):
    name = "secp256r1"

    def shared_secret(self, public_key_bytes: bytes, private_key_bytes: bytes) -> bytes:
        raise NotImplementedError()
