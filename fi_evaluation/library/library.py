from abc import ABC, abstractmethod
from typing import Iterable

from fi_evaluation.curve import Curve
from fi_evaluation.fault_finder.result import (SimulationResult,
                                               load_ordered_sim_results,
                                               print_sorted_simulation_results,
                                               read_processed_outputs)

PredictableOutputs = dict[bytes, tuple[int, set[SimulationResult]]]


class Library(ABC):
    """
    A class representing an evaluated library.
    It should represent a specific implementation of ECDH
    on a particular curve.
    """

    def __init__(self, curve: Curve, name: str):
        self.curve = curve
        self.name = name

    @abstractmethod
    def generate_computational_loop_abort_results(
            self, public_key: bytes, private_key: bytes) -> Iterable[tuple[bytes, int]]:
        pass

    def generate_known_outputs(self, public_key: bytes, private_key: bytes) -> Iterable[tuple[bytes, int]]:
        yield from self.curve.generate_known_outputs()
        yield from self.generate_computational_loop_abort_results(public_key, private_key)

    def print_predictable_outputs(self, predictable_outputs: PredictableOutputs, type_name: str):
        """
        Print the predictable outputs sorted by their entropy.
        A smaller entropy means easier to guess key/output - a bigger problem.
        type_name represents the type of predictable outputs, e.g. "Known output" or "Faulted key".
        """
        for output, (entropy, results) in sorted(predictable_outputs.items(), key=lambda item: item[1][0]):
            print(f"{type_name} - {output.hex()} ({entropy}).")
            print_sorted_simulation_results(results)
            print()

    def check_known_outputs(self, parsed_output: list[SimulationResult], known_outputs: dict[bytes, int]):
        seen_known_outputs: PredictableOutputs = {}
        for result_sim in parsed_output:
            output = result_sim.output
            if output in known_outputs:
                entropy = known_outputs[output]
                # The same known output might have been generated with different entropies.
                # We care about the smallest one.
                if output not in seen_known_outputs or entropy < seen_known_outputs[output][0]:
                    seen_known_outputs[output] = (entropy, {result_sim})
                else:
                    seen_known_outputs[output][1].add(result_sim)

        self.print_predictable_outputs(seen_known_outputs, "Known output")

    def check_key_shortening(self, parsed_output: list[SimulationResult], public_key: bytes, private_key: bytes):
        results_sim: dict[bytes, set[SimulationResult]] = {}
        for result_sim in parsed_output:
            if result_sim.output is None:
                continue
            if result_sim.output not in results_sim:
                results_sim[result_sim.output] = set()
            results_sim[result_sim.output].add(result_sim)

        seen_effective_keys: PredictableOutputs = {}
        for faulted_key, result, entropy in self.curve.generate_faulted_results(public_key, private_key):
            if result in results_sim:
                if faulted_key in seen_effective_keys:
                    if entropy < seen_effective_keys[faulted_key][0]:
                        # The same key might have been generated with different entropies.
                        # We care about the smallest one.
                        seen_effective_keys[faulted_key] = (entropy, seen_effective_keys[faulted_key][1])
                else:
                    seen_effective_keys[faulted_key] = (entropy, results_sim[result])

        self.print_predictable_outputs(seen_effective_keys, "Faulted key")

    def check_predictable_outputs(self, output_dir: str, public_key: bytes, private_key: bytes):
        # Need to cast to a list to be able to iterate multiple times
        parsed_output = list(read_processed_outputs(output_dir, skip_errors=True))
        self.check_key_shortening(parsed_output, public_key, private_key)
        known_outputs = self.generate_known_outputs(public_key, private_key)
        self.check_known_outputs(parsed_output, dict(known_outputs))

    def safe_error_leak(self, result_1: SimulationResult,
                        correct_output_1: bytes,
                        result_2: SimulationResult,
                        correct_output_2: bytes) -> bool:
        """
        Check if the two results leak in context of safe error.
        This means that one of them errored and the other did not or
        one of them contains the correct result and the other does not.
        """
        # Different outputs include one of them being empty (having the value of NO_OUTPUT).
        return (result_1.output == correct_output_1) ^ (result_2.output == correct_output_2) or \
               (result_1.errored != result_2.errored)

    def check_safe_error(self, output_dir_1: str, output_dir_2: str, public_key: bytes,
                         private_key_1: bytes, private_key_2: bytes):
        results_sim_1_ordered = load_ordered_sim_results(output_dir_1, skip_errors=False)
        results_sim_2_ordered = load_ordered_sim_results(output_dir_2, skip_errors=False)

        correct_output_1 = self.curve.shared_secret(public_key, private_key_1)
        correct_output_2 = self.curve.shared_secret(public_key, private_key_2)

        # No need to store the address explicitly, it is a part of the SimulationResult.
        potentially_prone_addresses: set[SimulationResult] = set()
        for fault_dict_1, fault_dict_2 in zip(results_sim_1_ordered, results_sim_2_ordered):
            for (fault_type, fault_target) in fault_dict_1.keys():
                if (fault_type, fault_target) not in fault_dict_2:
                    # The second result does not have the same fault.
                    continue

                result_sim_1 = fault_dict_1[(fault_type, fault_target)]
                result_sim_2 = fault_dict_2[(fault_type, fault_target)]

                assert result_sim_1.executed_instruction == result_sim_2.executed_instruction
                assert result_sim_1.fault.fault_type == result_sim_2.fault.fault_type
                assert result_sim_1.fault.target == result_sim_2.fault.target

                if self.safe_error_leak(result_sim_1, correct_output_1, result_sim_2, correct_output_2):
                    # Does not matter which result we use, we have already asserted
                    # that the important fields are the same in both.
                    potentially_prone_addresses.add(result_sim_1)

        print("Addresses potentially prone to safe error attack:")
        for result in sorted(potentially_prone_addresses, key=lambda r: r.executed_instruction.instruction):
            print(result)
