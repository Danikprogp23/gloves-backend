from pathlib import Path
import pickle
import traceback

import numpy as np
import pandas as pd
import tensorflow as tf

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

print("===== TRAIN START =====")

try:

    BASE_DIR = Path(__file__).resolve().parent

    CSV_PATH = BASE_DIR / "dataset.csv"
    TFLITE_PATH = BASE_DIR / "smartglove.tflite"
    KERAS_PATH = BASE_DIR / "gesture_model.keras"

    print("CSV:", CSV_PATH)

    if not CSV_PATH.exists():
        raise FileNotFoundError(
            f"dataset.csv not found: {CSV_PATH}"
        )

    df = pd.read_csv(CSV_PATH)

    print("DATASET LOADED")
    print("ROWS:", len(df))
    print("COLUMNS:", len(df.columns))

    LABEL_COLUMN = "gesture"

    if LABEL_COLUMN not in df.columns:
        raise ValueError(
            f"Column '{LABEL_COLUMN}' not found"
        )

    labels = df[LABEL_COLUMN].astype(str)
    features = df.drop(columns=[LABEL_COLUMN])

    features = features.apply(
        pd.to_numeric,
        errors="coerce"
    )

    features = features.fillna(0)

    features = features.astype("float32")

    label_encoder = LabelEncoder()

    y = label_encoder.fit_transform(
        labels
    )

    scaler = StandardScaler()

    X = scaler.fit_transform(
        features
    ).astype("float32")

    num_features = X.shape[1]
    num_classes = len(
        label_encoder.classes_
    )

    print("FEATURES:", num_features)
    print("CLASSES:", num_classes)

    if num_classes < 2:
        raise ValueError(
            "Need at least 2 gesture classes"
        )

    class_counts = (
        pd.Series(y)
        .value_counts()
    )

    can_stratify = (
        class_counts.min() >= 2
    )

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y if can_stratify else None
        )
    )

    print("TRAIN SAMPLES:", len(X_train))
    print("TEST SAMPLES:", len(X_test))

    model = tf.keras.Sequential([
        tf.keras.layers.Input(
            shape=(num_features,)
        ),

        tf.keras.layers.Dense(
            64,
            activation="relu"
        ),

        tf.keras.layers.Dense(
            32,
            activation="relu"
        ),

        tf.keras.layers.Dense(
            num_classes,
            activation="softmax"
        )
    ])

    model.compile(
        optimizer="adam",
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )

    print("MODEL FIT START")

    model.fit(
        X_train,
        y_train,
        validation_data=(
            X_test,
            y_test
        ),
        epochs=20,
        batch_size=8,
        verbose=1
    )

    print("MODEL FIT END")

    loss, acc = model.evaluate(
        X_test,
        y_test,
        verbose=0
    )

    print(
        f"ACCURACY = {acc:.4f}"
    )

    model.save(
        KERAS_PATH
    )

    print("KERAS SAVED")

    with open(
        BASE_DIR / "label_encoder.pkl",
        "wb"
    ) as f:
        pickle.dump(
            label_encoder,
            f
        )

    with open(
        BASE_DIR / "scaler.pkl",
        "wb"
    ) as f:
        pickle.dump(
            scaler,
            f
        )

    with open(
        BASE_DIR / "labels.txt",
        "w",
        encoding="utf-8"
    ) as f:

        for label in (
            label_encoder.classes_
        ):
            f.write(
                str(label) + "\n"
            )

    print("LABELS SAVED")

    converter = (
        tf.lite.TFLiteConverter
        .from_keras_model(model)
    )

    tflite_model = (
        converter.convert()
    )

    with open(
        TFLITE_PATH,
        "wb"
    ) as f:

        f.write(
            tflite_model
        )

    print("TFLITE SAVED")
    print("===== TRAIN SUCCESS =====")

except Exception as e:

    print("===== TRAIN FAILED =====")
    print(str(e))
    traceback.print_exc()

    raise