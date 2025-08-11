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
    parser_check_predictable.add_argument("public_key", type=str)
    parser_check_predictable.add_argument("private_key", type=str)

    parser_check_safe_error = subparsers.add_parser("check-safe-error")
    parser_check_safe_error.add_argument("output_dir_1", type=str)
    parser_check_safe_error.add_argument("output_dir_2", type=str)
    parser_check_safe_error.add_argument("public_key", type=str)
    parser_check_safe_error.add_argument("private_key_1", type=str)
    parser_check_safe_error.add_argument("private_key_2", type=str)

    library = Sca25519Unprotected()  # TODO: This should probably be parsed from the arguments.
    args = parser.parse_args()

    if args.command == "check-predictable":
        public_key_bytes = bytes.fromhex(args.public_key)
        private_key_bytes = bytes.fromhex(args.private_key)
        library.check_predictable_outputs(args.output_dir, public_key_bytes, private_key_bytes)

    elif args.command == "check-safe-error":
        public_key = bytes.fromhex(args.public_key)
        private_key_1_bytes = bytes.fromhex(args.private_key_1)
        private_key_2_bytes = bytes.fromhex(args.private_key_2)
        library.check_safe_error(
            args.output_dir_1,
            args.output_dir_2,
            public_key,
            private_key_1_bytes,
            private_key_2_bytes)


if __name__ == "__main__":
    main()
