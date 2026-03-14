"""Portable Random Forest runtime helpers for controller-side inference.

The live controller container intentionally stays lightweight and does not
install the full offline training stack. This module provides a small
pickle-friendly representation of a fitted scikit-learn Random Forest so the
controller can perform inference without importing sklearn.
"""

from dataclasses import dataclass, field


LEAF_NODE = -1


@dataclass
class RuntimeDecisionTree(object):
    """Serialized decision tree arrays exported from sklearn."""

    children_left: list
    children_right: list
    feature: list
    threshold: list
    values: list

    def predict_leaf_values(self, feature_vector):
        """Traverse the tree and return the class counts stored at the leaf."""

        node_index = 0
        while True:
            left_index = self.children_left[node_index]
            right_index = self.children_right[node_index]
            if left_index == LEAF_NODE and right_index == LEAF_NODE:
                return list(self.values[node_index])

            feature_index = self.feature[node_index]
            threshold = float(self.threshold[node_index])
            feature_value = (
                float(feature_vector[feature_index])
                if 0 <= feature_index < len(feature_vector)
                else 0.0
            )
            if feature_value <= threshold:
                node_index = left_index
            else:
                node_index = right_index


@dataclass
class RuntimeRandomForestModel(object):
    """Pure-Python Random Forest inference model used at runtime."""

    classes_: list
    trees: list = field(default_factory=list)

    def predict(self, rows):
        predictions = []
        for probabilities in self.predict_proba(rows):
            winning_index = max(
                range(len(probabilities)),
                key=lambda index: probabilities[index],
            )
            predictions.append(self.classes_[winning_index])
        return predictions

    def predict_proba(self, rows):
        return [self._predict_proba_row(row) for row in rows]

    def _predict_proba_row(self, feature_vector):
        if not self.trees:
            class_count = max(len(self.classes_), 1)
            return [1.0 / float(class_count)] * class_count

        aggregated = [0.0] * len(self.classes_)
        for tree in self.trees:
            leaf_values = tree.predict_leaf_values(feature_vector)
            total = float(sum(leaf_values))
            if total <= 0.0:
                continue
            for index, value in enumerate(leaf_values):
                aggregated[index] += float(value) / total

        tree_count = float(len(self.trees))
        if tree_count <= 0.0:
            class_count = max(len(self.classes_), 1)
            return [1.0 / float(class_count)] * class_count
        return [value / tree_count for value in aggregated]


def export_random_forest_model(classifier):
    """Convert a fitted sklearn RandomForestClassifier into a portable model."""

    estimators = list(getattr(classifier, "estimators_", []) or [])
    classes = [str(value) for value in getattr(classifier, "classes_", [])]
    trees = []

    for estimator in estimators:
        tree = estimator.tree_
        trees.append(
            RuntimeDecisionTree(
                children_left=tree.children_left.tolist(),
                children_right=tree.children_right.tolist(),
                feature=tree.feature.tolist(),
                threshold=[float(value) for value in tree.threshold.tolist()],
                values=[
                    [float(class_count) for class_count in node_values[0].tolist()]
                    for node_values in tree.value
                ],
            )
        )

    return RuntimeRandomForestModel(classes_=classes, trees=trees)
