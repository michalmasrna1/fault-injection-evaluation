import argparse
import os

from fi_evaluation.curve import supported_curve_names
from fi_evaluation.fault_finder import (SimulationResult, count_total_faults,
                                        print_sorted_simulation_results,
                                        read_processed_outputs,
                                        simulate_faults_parallel)
from fi_evaluation.library import (PredictableOutputs, library_from_name,
                                   supported_library_names)
from fi_evaluation.safe_error import (evaluate_safe_error,
                                      print_safe_error_results,
                                      safe_error_model_from_name,
                                      supported_leakage_model_names)

EXECUTABLE_DIR = os.path.dirname(os.path.abspath(__file__))
# Could be parsed from the command line but for now all evaluations use the same buffer content.
OUTPUT_BUFFER = bytes.fromhex("ecc25519ecc25519ecc25519ecc25519ecc25519ecc25519ecc25519ecc25519")


def print_predictable_outputs(predictable_outputs: PredictableOutputs, type_name: str):
    """
    Print the predictable outputs sorted by their entropy.
    A smaller entropy means easier to guess key/output - a bigger problem.
    type_name represents the type of predictable outputs, e.g. "Known output" or "Faulted key".
    """
    for output, (entropy, results) in sorted(predictable_outputs.items(), key=lambda item: item[1][0]):
        print(f"{type_name} - {output.hex()} ({entropy}).")
        print_sorted_simulation_results(results)
    print()


def print_predictable_outputs_summary(predictable_outputs: PredictableOutputs, type_name: str):
    """
    Print the number of successful faults for each predictable output
    sorted by the number of successful faults, and secondary by entropy.
    """
    print(f"Summary of {type_name}s:")
    print(f"Total: {sum(len(results) for (_, results) in predictable_outputs.values())} successful faults.")
    for output, (entropy, results) in sorted(predictable_outputs.items(),
                                             key=lambda item: (len(item[1][1]), item[1][0]), reverse=True):
        print(f"{output.hex()} ({entropy}): {len(results)} successful faults.")
    print()


def print_output_distribution(processed_outputs: list[SimulationResult], correct_output: bytes):
    """
    Print the distribution of faulted outputs in the processed outputs.
    """
    output_counts: dict[bytes, int] = {}
    for result in processed_outputs:
        output = result.output
        if output is None:
            continue
        output_counts[output] = output_counts.get(output, 0) + 1

    total_outputs = sum(output_counts.values())

    print("Total number of outputs:", total_outputs)
    print(" - faults which cause no output (crash) are not counted.")
    print("Most common outputs:")
    for output, count in sorted(output_counts.items(), key=lambda item: item[1], reverse=True):
        relative_count = count / total_outputs
        if relative_count >= 0.0001:
            print(f"{output.hex()}: {count} ({relative_count * 100:.2f}%)."
                  f"{' (the correct result)' if output == correct_output else ''}")
    print()


def main():
    command_parser = argparse.ArgumentParser()
    subparsers = command_parser.add_subparsers(dest="command")
    subparsers.required = True

    parser_check_predictable = subparsers.add_parser("check-predictable",
                                                     help="Check predictable-result fault-injection attacks.")
    parser_check_safe_error = subparsers.add_parser("check-safe-error",
                                                    help="Check safe-error susceptible addresses for one key pair.")
    parser_evaluate_safe_error = subparsers.add_parser("evaluate-safe-error",
                                                       help="Evaluate safe-error susceptible addresses of a library. "
                                                            "Calls check-safe-error repeatedly.")
    parser_simulate_parallel = subparsers.add_parser("simulate-parallel",
                                                     help="Run multiple instances of fault finder in parallel "
                                                          "for optimized performance.")

    # Library and curve all required for all commands.
    for parser in (parser_check_predictable, parser_check_safe_error,
                   parser_evaluate_safe_error, parser_simulate_parallel):
        parser.add_argument("library_name", type=str, choices=supported_library_names(),
                            help="The name of the library to evaluate.")
        parser.add_argument("curve_name", type=str, choices=supported_curve_names(),
                            help="The name of the curve to use for the evaluation.")

    # check-predictable
    parser_check_predictable.add_argument("output_dir", type=str,
                                          help="Path to the directory that contains the fault-finder outputs "
                                               "(processed to .bin).")
    parser_check_predictable.add_argument("private_key", type=str,
                                          help="The private key (scalar) used for the evaluation.")

    # check-safe-error
    parser_check_safe_error.add_argument("output_dir_1", type=str,
                                         help="Path to the directory that contains the fault-finder outputs "
                                              "(processed to .bin) for the first key.")
    parser_check_safe_error.add_argument("output_dir_2", type=str,
                                         help="Path to the directory that contains the fault-finder outputs "
                                              "(processed to .bin) for the second key.")
    parser_check_safe_error.add_argument("private_key_1", type=str,
                                         help="The first private key (scalar) used for the evaluation.")
    parser_check_safe_error.add_argument("private_key_2", type=str,
                                         help="The second (complementary) private key "
                                              "(scalar) used for the evaluation.")

    # evaluate-safe-error
    parser_evaluate_safe_error.add_argument("safe_error_model", type=str, choices=supported_leakage_model_names(),
                                            help="The leakage model to use for the evaluation.")
    parser_evaluate_safe_error.add_argument("first_key", type=str, nargs='?', default=None,
                                            help="If provided, the private key(s) in the first iteration are not "
                                                 "generated randomly, but the provided value and its complement are "
                                                 "used. Should be used to avoid the expensive first iteration if "
                                                 "results for some scalar pair are already computed.")

    # simulate-parallel
    parser_simulate_parallel.add_argument("optimal_threads", type=int, nargs='?', default=None,
                                          help="The number of threads per fault-finder instance. "
                                               "The ideal number should be determined outside this script. "
                                               "If no value is provided, the script will attempt to read "
                                               "an environment variable FF_OPT_THREADS. If that is not present "
                                               "either, 8 is used.")

    # Add public_key to the commands which use it.
    # Added as the last argument so that it can be optional.
    for parser in (parser_check_predictable, parser_check_safe_error, parser_evaluate_safe_error):
        parser.add_argument("public_key", type=str, nargs='?', default=None,
                            help="The public key used for the evaluation. Defaults to the curve's base point.")

    args = command_parser.parse_args()
    library = library_from_name(args.library_name, args.curve_name)

    # Not the best place for this command as it is technically not
    # an "evaluation", but lets not over-engineer.
    if args.command == "simulate-parallel":
        if args.optimal_threads is None:
            simulate_faults_parallel(library)
        else:
            simulate_faults_parallel(library, args.optimal_threads)
        # Return to avoid parsing the public key argument.
        return

    if args.public_key is None:
        print("No public key specified, using the base point.")
        pub_key_bytes = library.curve.base_point()
    else:
        pub_key_bytes = bytes.fromhex(args.public_key)

    if args.command == "check-predictable":
        priv_key_bytes = bytes.fromhex(args.private_key)
        # Need to cast to a list to be able to iterate multiple times.
        parsed_output = list(read_processed_outputs(args.output_dir, skip_errors=True))

        loop_abort_results = library.check_computational_loop_abort(parsed_output, pub_key_bytes, priv_key_bytes)
        print_predictable_outputs(loop_abort_results, "Loop abort output")

        key_shortening_results = library.check_key_shortening(parsed_output, pub_key_bytes, priv_key_bytes)
        print_predictable_outputs(key_shortening_results, "Faulted key")

        fixed_output_results = library.check_output_fixing(parsed_output, pub_key_bytes, priv_key_bytes, OUTPUT_BUFFER)
        print_predictable_outputs(fixed_output_results, "Fixed output")

        print("Total number of faults: ", count_total_faults(args.output_dir))
        correct_output = library.curve.shared_secret(pub_key_bytes, priv_key_bytes)
        print_output_distribution(parsed_output, correct_output)

        # Print the summaries at the end for visibility.
        print_predictable_outputs_summary(loop_abort_results, "Loop abort output")
        print()
        print_predictable_outputs_summary(key_shortening_results, "Faulted key")
        print()
        print_predictable_outputs_summary(fixed_output_results, "Fixed output")

    elif args.command == "check-safe-error":
        private_key_1_bytes = bytes.fromhex(args.private_key_1)
        private_key_2_bytes = bytes.fromhex(args.private_key_2)
        potentially_prone_addresses = library.check_safe_error(
            args.output_dir_1,
            args.output_dir_2,
            pub_key_bytes,
            private_key_1_bytes,
            private_key_2_bytes
        )
        print_safe_error_results(potentially_prone_addresses, group=True)

    elif args.command == "evaluate-safe-error":
        safe_error_model = safe_error_model_from_name(args.safe_error_model)
        first_key = bytes.fromhex(args.first_key) if args.first_key else None
        evaluate_safe_error(library, pub_key_bytes, safe_error_model, first_key)


if __name__ == "__main__":
    main()
