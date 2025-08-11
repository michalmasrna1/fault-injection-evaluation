import argparse
import os

from fi_evaluation.library import Sca25519Unprotected

EXECUTABLE_DIR = os.path.dirname(os.path.abspath(__file__))


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    parser_check_predictable = subparsers.add_parser("check-predictable")
    parser_check_predictable.add_argument("output_dir", type=str)
    parser_check_predictable.add_argument("key", type=str)

    parser_check_safe_error = subparsers.add_parser("check-safe-error")
    parser_check_safe_error.add_argument("output_dir_1", type=str)
    parser_check_safe_error.add_argument("output_dir_2", type=str)
    parser_check_safe_error.add_argument("key_1", type=str)
    parser_check_safe_error.add_argument("key_2", type=str)

    library = Sca25519Unprotected()  # TODO: This should probably be parsed from the arguments.
    args = parser.parse_args()

    if args.command == "check-predictable":
        key_bytes = bytes.fromhex(args.key)
        library.check_predictable_outputs(args.output_dir, key_bytes)

    elif args.command == "check-safe-error":
        key_1_bytes = bytes.fromhex(args.key_1)
        key_2_bytes = bytes.fromhex(args.key_2)
        library.check_safe_error(args.output_dir_1, args.output_dir_2, key_1_bytes, key_2_bytes)


if __name__ == "__main__":
    main()
