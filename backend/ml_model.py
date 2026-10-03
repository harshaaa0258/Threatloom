"""Shared model construction for inference and offline evaluation."""


def build_email_ml_pipeline():
    """Build the same word/character TF-IDF classifier used by analysis."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    return Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(
                stop_words="english",
                ngram_range=(1, 2),
                sublinear_tf=True,
                max_features=20000,
            )),
            ("character", TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                sublinear_tf=True,
                max_features=20000,
            )),
        ])),
        ("clf", LogisticRegression(
            max_iter=1500,
            class_weight="balanced",
            solver="lbfgs",
        )),
    ])
