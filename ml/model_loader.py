"""Persistence helpers for the optional ML IDS model bundle."""

from dataclasses import dataclass, field
from pathlib import Path
import pickle

from ml.feature_extractor import RUNTIME_FEATURE_NAMES

try:
    import joblib
except ImportError:  # pragma: no cover - optional dependency
    joblib = None


@dataclass
class ModelBundle(object):
    """Loaded model plus metadata required for runtime inference."""

    model: object = None
    feature_names: tuple = field(default_factory=lambda: tuple(RUNTIME_FEATURE_NAMES))
    positive_labels: tuple = field(default_factory=tuple)
    metadata: dict = field(default_factory=dict)
    source_path: str = ""
    load_error: str = None

    @property
    def is_available(self):
        return self.model is not None and not self.load_error


def load_model(model_path, fallback_feature_names=None, fallback_positive_labels=None):
    """Load a serialized model bundle from disk.

    The saved payload may be either:
    - a dictionary with keys such as model, feature_names, metadata
    - a bare estimator object
    """

    feature_names = tuple(fallback_feature_names or RUNTIME_FEATURE_NAMES)
    positive_labels = tuple(fallback_positive_labels or ())

    if not model_path:
        return ModelBundle(
            feature_names=feature_names,
            positive_labels=positive_labels,
            load_error="ml_model_path_not_configured",
        )

    bundle_path = Path(model_path)
    if not bundle_path.exists():
        return ModelBundle(
            feature_names=feature_names,
            positive_labels=positive_labels,
            source_path=str(bundle_path),
            load_error="ml_model_file_not_found",
        )

    payload, error_message = _deserialize_payload(bundle_path)
    if error_message is not None:
        return ModelBundle(
            feature_names=feature_names,
            positive_labels=positive_labels,
            source_path=str(bundle_path),
            load_error=error_message,
        )

    if isinstance(payload, dict):
        model = payload.get("model")
        feature_names = tuple(payload.get("feature_names") or feature_names)
        positive_labels = tuple(payload.get("positive_labels") or positive_labels)
        metadata = dict(payload.get("metadata") or {})
    else:
        model = payload
        metadata = {}

    return ModelBundle(
        model=model,
        feature_names=feature_names,
        positive_labels=positive_labels,
        metadata=metadata,
        source_path=str(bundle_path),
    )


def save_model_bundle(model_path, payload):
    """Persist a model bundle using pickle for runtime portability.

    The runtime controller image does not need the heavier offline training
    stack. Saving with pickle keeps the artifact loadable without installing
    joblib in the controller container, while load_model() still accepts either
    pickle or joblib-created bundles.
    """

    bundle_path = Path(model_path)
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    with bundle_path.open("wb") as handle:
        pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)


def _deserialize_payload(bundle_path):
    if joblib is not None:
        try:
            return joblib.load(str(bundle_path)), None
        except Exception as exc:  # pragma: no cover - defensive fallback
            joblib_error = str(exc)
        else:  # pragma: no cover - unreachable, for clarity
            joblib_error = None
    else:
        joblib_error = "joblib_unavailable"

    try:
        with bundle_path.open("rb") as handle:
            return pickle.load(handle), None
    except Exception as exc:  # pragma: no cover - defensive fallback
        return None, "joblib_error=%s pickle_error=%s" % (joblib_error, exc)
