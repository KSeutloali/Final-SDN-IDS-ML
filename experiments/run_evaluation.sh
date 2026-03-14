#!/bin/sh
set -eu

exec python3 experiments/run_evaluation.py "$@"

