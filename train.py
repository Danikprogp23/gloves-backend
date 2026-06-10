from pathlib import Path
import pickle

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

BASE_DIR = Path(__file__).resolve().parent

CSV_PATH = BASE_DIR / "dataset.csv"
TFLITE_PATH = BASE_DIR / "smartglove.tflite"
KERAS_PATH = BASE_DIR / "gesture_model.keras"

df = pd.read_csv(CSV_PATH)

LABEL_COLUMN = "gesture"

if LABEL_COLUMN not in df.columns:
    raise ValueError(f"В dataset.csv должен быть столбец {LABEL_COLUMN}")

labels = df[LABEL_COLUMN].astype(str)
features = df.drop(columns=[LABEL_COLUMN])

features = features.apply(pd.to_numeric, errors="coerce")
features = features.fillna(0).astype("float32")

label_encoder = LabelEncoder()
y = label_encoder.fit_transform(labels)

scaler = StandardScaler()
X = scaler.fit_transform(features).astype("float32")

num_features = X.shape[1]
num_classes = len(label_encoder.classes_)

if num_classes < 2:
    raise ValueError("Нужно минимум 2 разных жеста в dataset.csv")

class_counts = pd.Series(y).value_counts()
can_stratify = class_counts.min() >= 2

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y if can_stratify else None
)

model = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(num_features,)),
    tf.keras.layers.Dense(128, activation="relu"),
    tf.keras.layers.Dropout(0.25),
    tf.keras.layers.Dense(64, activation="relu"),
    tf.keras.layers.Dropout(0.20),
    tf.keras.layers.Dense(num_classes, activation="softmax")
])

model.compile(
    optimizer="adam",
    loss="sparse_categorical_crossentropy",
    metrics=["accuracy"]
)

model.fit(
    X_train,
    y_train,
    validation_data=(X_test, y_test),
    epochs=80,
    batch_size=16
)

loss, acc = model.evaluate(X_test, y_test)
print(f"Accuracy: {acc:.4f}")

model.save(KERAS_PATH)

with open(BASE_DIR / "label_encoder.pkl", "wb") as f:
    pickle.dump(label_encoder, f)

with open(BASE_DIR / "scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

with open(BASE_DIR / "labels.txt", "w", encoding="utf-8") as f:
    for label in label_encoder.classes_:
        f.write(str(label) + "\n")

print("START TFLITE CONVERT")

converter = tf.lite.TFLiteConverter.from_keras_model(model)

converter.experimental_enable_resource_variables = True

converter.target_spec.supported_ops = [
    tf.lite.OpsSet.TFLITE_BUILTINS,
    tf.lite.OpsSet.SELECT_TF_OPS
]

tflite_model = converter.convert()

print("END TFLITE CONVERT")

with open(TFLITE_PATH, "wb") as f:
    f.write(tflite_model)

with open(TFLITE_PATH, "wb") as f:
    f.write(tflite_model)

print("Saved:", TFLITE_PATH)
print("Classes:", list(label_encoder.classes_))
print("Input features:", num_features)