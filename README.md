# Fault Injection Evaluation

This repository contains scripts to evaluate the resistance of an ECDH implementation against fault-injection attacks.

The repository accompanies the master's thesis titled "Simulation-based fault-injection evaluation methodology for cryptolibraries". A link will be provided once the thesis is published.

## Description

All repository code is contained in the `fi_evaluation` directory. Most of the scripts focus on analyzing outputs from the open-source fault-injection simulator [`fault-finder`](https://github.com/fault-finder/fault-finder) to determine the resistance of ECDH implementations to fault-injection attacks. The code is prepared to work with this [fork](https://github.com/michalmasrna1/fault-finder) of the `fault-finder` repository and was not tested with the original.

The directory `key_exchange_results` contains precomputed ECDH results to save computation time during repeated evaluations. It includes a subdirectory for each elliptic curve. In the subdirectories, the `<public_point>.json` files contain mappings from private scalars to results, all in hexadecimal format.

## Usage

The repository contains a Pipenv package. To install Pipenv, follow these [instructions](https://pipenv.pypa.io/en/latest/installation.html). To install the dependencies, run

```
pipenv install
```

and then

```
pipenv shell
```

which will spawn a new shell with the virtual environment with all the dependencies activated. From there, you can run

```
python fi_evaluation/evaluate.py <command> <args>
```

The available commands are described in the next section.

### Commands

The main entry point to the repository is the file `fi_evaluation/evaluate.py`. This file contains four commands:

1. `check-predictable` - Evaluate a library against fault-injection attacks that produce predictable results. These are:
        
    - key shortening
    - computational loop-abort attack
    - fixing the scalar multiplication output
    - small subgroup attack on Curve25519
    - invalid curve attack on secp256k1

2. `check-safe-error` - Determine the instructions susceptible to safe-error attack according to the provided leakage model for one scalar pair.

3. `evaluate-safe-error` - Evaluate a library's resistance to safe-error attack according to the provided leakage model. Calls `check-safe-error` repeatedly.

4. `simulate-parallel` - Run a `fault-finder` simulation campaign on multiple `fault-finder` instances. Leads to better CPU utilization and faster results.

Calling

```
python fi_evaluation/evaluate.py -h
```

or

```
python fi_evaluation/evaluate.py <command> -h
```

will print more details on the individual commands and their arguments.

## Configuration

The `simulate-parallel` and `evaluate-safe-error` commands need to know the path to the `fault-finder` directory to run it and change its configuration.
This can be configured via the `.env` file, which contains the `FAULT_FINDER_PATH` variable.
The path can be an absolute path or a relative path to the repository's base. The default is `../fault-finder`, which assumes the `fault-finder` directory is in the same parent directory as this repository.
The code assumes `faultfinder` is compiled in that directory and that its configuration directory structure matches that of the forked repository.
