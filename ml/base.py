"""Minimal interface for later ML-based IDS components."""


class BaseMLDetector(object):
    """Common interface for future ML detectors."""

    def fit(self, samples, labels=None):
        raise NotImplementedError("fit() must be implemented by subclasses")

    def predict(self, features):
        raise NotImplementedError("predict() must be implemented by subclasses")
