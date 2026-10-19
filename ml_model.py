import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix

from rules import CATEGORIES
from features import FEATURE_COLUMNS
from block_evasion import LINKING_FEATURE_COLUMNS

ML_FEATURE_COLUMNS = FEATURE_COLUMNS + LINKING_FEATURE_COLUMNS

try:
    from xgboost import XGBClassifier

    HAVE_XGBOOST = True
except ImportError:
    HAVE_XGBOOST = False

def build_ml_table(feat_df_with_links, ground_truth_df):
    return feat_df_with_links.merge(
        ground_truth_df[["ip", "user_agent", "category"]], on=["ip", "user_agent"], how="left"
    )

def _make_model(random_state):
    if HAVE_XGBOOST:
        return (
            XGBClassifier(
                n_estimators=200,
                max_depth=4,
                learning_rate=0.1,
                subsample=0.9,
                colsample_bytree=0.9,
                random_state=random_state,
                eval_metric="mlogloss",
            ),
            "XGBoost",
        )
    return (
        RandomForestClassifier(
            n_estimators=300,
            max_depth=7,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=random_state,
        ),
        "RandomForest",
    )

def train_and_evaluate(ml_table, feature_cols=ML_FEATURE_COLUMNS, n_splits=5, random_state=42):
    X = ml_table[feature_cols].fillna(0.5).reset_index(drop=True)
    y = ml_table["category"].reset_index(drop=True)
    classes = CATEGORIES

    oof_pred = pd.Series(index=X.index, dtype=object)
    oof_proba = pd.DataFrame(index=X.index, columns=classes, dtype=float)
    model_name = None

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    for train_idx, test_idx in skf.split(X, y):
        fold_model, model_name = _make_model(random_state)
        if model_name == "XGBoost":
            label_to_int = {c: i for i, c in enumerate(classes)}
            int_to_label = {i: c for c, i in label_to_int.items()}
            fold_model.fit(X.iloc[train_idx], y.iloc[train_idx].map(label_to_int))
            proba = fold_model.predict_proba(X.iloc[test_idx])
            fold_classes = [int_to_label[i] for i in fold_model.classes_]
        else:
            fold_model.fit(X.iloc[train_idx], y.iloc[train_idx])
            proba = fold_model.predict_proba(X.iloc[test_idx])
            fold_classes = list(fold_model.classes_)

        proba_df = pd.DataFrame(proba, index=X.index[test_idx], columns=fold_classes)
        for c in classes:
            oof_proba.loc[proba_df.index, c] = proba_df[c] if c in proba_df.columns else 0.0
        oof_pred.loc[X.index[test_idx]] = proba_df.idxmax(axis=1)

    report = classification_report(y, oof_pred, labels=CATEGORIES, output_dict=True, zero_division=0)
    cm = confusion_matrix(y, oof_pred, labels=CATEGORIES)

    final_model, _ = _make_model(random_state)
    if model_name == "XGBoost":
        label_to_int = {c: i for i, c in enumerate(classes)}
        final_model.fit(X, y.map(label_to_int))
    else:
        final_model.fit(X, y)
    importances = getattr(final_model, "feature_importances_", np.zeros(len(feature_cols)))
    feature_importance = dict(sorted(zip(feature_cols, importances.tolist()), key=lambda kv: -kv[1]))

    return {
        "model": final_model,
        "model_name": model_name,
        "feature_cols": feature_cols,
        "oof_pred": oof_pred,
        "oof_proba": oof_proba,
        "report": report,
        "confusion_matrix": cm,
        "feature_importance": feature_importance,
        "classes": classes,
    }

def build_shap_explainer(model, model_name, background_X):
    try:
        import shap

        return shap.TreeExplainer(model)
    except Exception:
        return None

def explain_instance(x_row, feature_cols, feature_importance, predicted_class, classes, shap_explainer=None):
    if shap_explainer is not None:
        try:
            sv = shap_explainer(x_row.to_frame().T)
            class_idx = list(classes).index(predicted_class) if predicted_class in list(classes) else 0
            values = sv.values[0, :, class_idx] if sv.values.ndim == 3 else sv.values[0]
            pairs = sorted(zip(feature_cols, values), key=lambda kv: -abs(kv[1]))[:3]
            return [{"feature": f, "shap_value": float(v)} for f, v in pairs]
        except Exception:
            pass
    top_feats = list(feature_importance.keys())[:3]
    return [{"feature": f, "value": float(x_row[f])} for f in top_feats]
