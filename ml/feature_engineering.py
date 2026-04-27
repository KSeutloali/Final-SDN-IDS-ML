"""Shared feature-engineering helpers for live and offline ML feature generation."""

from collections import defaultdict
import math


def standard_deviation(values):
    numeric_values = [float(value) for value in values]
    if len(numeric_values) < 2:
        return 0.0
    mean_value = sum(numeric_values) / float(len(numeric_values))
    variance = sum(
        (value - mean_value) ** 2 for value in numeric_values
    ) / float(len(numeric_values))
    return math.sqrt(variance)


def inter_arrival_stats(timestamps):
    timestamp_values = [float(value) for value in timestamps]
    if len(timestamp_values) < 2:
        return 0.0, 0.0
    deltas = [
        max(0.0, current - previous)
        for previous, current in zip(timestamp_values, timestamp_values[1:])
    ]
    if not deltas:
        return 0.0, 0.0
    mean_value = sum(deltas) / float(len(deltas))
    return mean_value, standard_deviation(deltas)


def burstiness(mean_value, std_value):
    denominator = float(mean_value) + float(std_value)
    if denominator <= 0.0:
        return 0.0
    return (float(std_value) - float(mean_value)) / denominator


def entropy(values):
    counts = defaultdict(int)
    total = 0
    for value in values:
        if value in (None, ""):
            continue
        counts[value] += 1
        total += 1
    if total <= 1:
        return 0.0
    entropy_value = 0.0
    for count in counts.values():
        probability = float(count) / float(total)
        entropy_value -= probability * math.log(probability, 2)
    return entropy_value


def new_value_ratio(current_values, historical_values):
    current_set = {value for value in current_values if value not in (None, "")}
    if not current_set:
        return 0.0
    historical_set = {
        value for value in historical_values if value not in (None, "")
    }
    return float(len(current_set - historical_set)) / float(len(current_set))


def baseline_ratio(current_value, baseline_value):
    current_value = float(current_value or 0.0)
    if baseline_value is None:
        return 1.0 if current_value > 0.0 else 0.0
    baseline_value = float(baseline_value)
    if baseline_value <= 0.0:
        return 1.0 if current_value > 0.0 else 0.0
    return current_value / baseline_value


def trend_delta(current_value, reference_value):
    return float(current_value or 0.0) - float(reference_value or 0.0)
