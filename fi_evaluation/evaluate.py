import argparse
import os
from typing import Iterable

from fi_evaluation.library import Sca25519Unprotected

EXECUTABLE_DIR = os.path.dirname(os.path.abspath(__file__))


def save_known_outputs(known_outputs: Iterable[tuple[bytes, int]], path: str):
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as known_outputs_file:
        for computational_loop_abort_key, entropy in known_outputs:
            known_outputs_file.write(f"{computational_loop_abort_key.hex()},{entropy}\n")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    parser_check_key_shortening = subparsers.add_parser("save-known-outputs")
    parser_check_key_shortening.add_argument("key", type=str)
    parser_check_key_shortening.add_argument("known_outputs_path", type=str)

    parser_check_predictable = subparsers.add_parser("check-predictable")
    parser_check_predictable.add_argument("output_dir", type=str)
    parser_check_predictable.add_argument("key", type=str)
    parser_check_predictable.add_argument("known_outputs_path", type=str)

    parser_check_safe_error = subparsers.add_parser("check-safe-error")
    parser_check_safe_error.add_argument("output_dir_1", type=str)
    parser_check_safe_error.add_argument("output_dir_2", type=str)
    parser_check_safe_error.add_argument("key_1", type=str)
    parser_check_safe_error.add_argument("key_2", type=str)

    library = Sca25519Unprotected()  # TODO: This should probably be parsed from the arguments.
    args = parser.parse_args()
    if args.command == "save-known-outputs":
        key_bytes = bytes.fromhex(args.key)
        save_known_outputs(library.generate_known_outputs(key_bytes), args.known_outputs_path)

    if args.command == "check-predictable":
        key_bytes = bytes.fromhex(args.key)
        library.check_predictable_outputs(args.output_dir, key_bytes, args.known_outputs_path)

    elif args.command == "check-safe-error":
        key_1_bytes = bytes.fromhex(args.key_1)
        key_2_bytes = bytes.fromhex(args.key_2)
        library.check_safe_error(args.output_dir_1, args.output_dir_2, key_1_bytes, key_2_bytes)


if __name__ == "__main__":
    main()
