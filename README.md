# Fault Injection Evaluation

This repository contains scripts to evaluate the resistance of an ECDH implementation against fault-injection attacks.

The repository accompanies the master's thesis titled "Simulation-based fault-injection evaluation methodology for cryptolibraries". A link will be provided once the thesis is published.

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
    - invalid curve attack on secp25k1

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