from fi_evaluation.curve import curve_from_name
from fi_evaluation.library.library import Library, PredictableOutputs
from fi_evaluation.library.micro_ecc import MicroECC
from fi_evaluation.library.sca25519 import (Sca25519Ephemeral, Sca25519Static,
                                            Sca25519Unprotected)
from fi_evaluation.library.sweet_b import SweetB


def library_from_name(library_name: str, curve_name: str) -> Library:
    for library in (MicroECC, Sca25519Ephemeral, Sca25519Static,
                    Sca25519Unprotected, SweetB):
        if library.name.lower() == library_name.lower():
            return library(curve=curve_from_name(curve_name))
    raise ValueError(f"Unknown library name: {library_name}. Known library names are:\n- " +
                     "\n- ".join(lib.name for lib in (MicroECC, Sca25519Ephemeral, Sca25519Static,
                                                      Sca25519Unprotected, SweetB)))
