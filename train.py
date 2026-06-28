# =============================================================
# train.py — CNN Signal Classifier on RadioML 2018.01A Dataset
# Run this on Kaggle Notebook (GPU recommended)
# =============================================================

import numpy as np
import pickle
import os
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
import seaborn as sns

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import (
    Conv1D, MaxPooling1D, Dropout, Flatten, Dense, BatchNormalization
)
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

# ─────────────────────────────────────────
# 1. LOAD DATASET
# ─────────────────────────────────────────
# On Kaggle: dataset path is /kaggle/input/radioml2018/GOLD_XYZ_OSC.0001_1024.hdf5
# We support both HDF5 (Kaggle) and pickle format

def load_dataset(path=None):
    """
    Load RadioML 2018.01A dataset.
    Supports HDF5 (from Kaggle) or pickle format.
    Returns X (signals), Y (labels), snr array.
    """
    # Try HDF5 first (Kaggle native)
    hdf5_path = path or "/kaggle/input/radioml2018/GOLD_XYZ_OSC.0001_1024.hdf5"
    pkl_path   = path or "data/dataset.pkl"

    if os.path.exists(hdf5_path):
        import h5py
        print(f"[✓] Loading HDF5 dataset from {hdf5_path}")
        with h5py.File(hdf5_path, "r") as f:
            X   = f["X"][:]    # shape: (2555904, 1024, 2)
            Y   = f["Y"][:]    # one-hot encoded
            snr = f["Z"][:]    # SNR values
        print(f"    X shape : {X.shape}")
        print(f"    Y shape : {Y.shape}")
        return X, Y, snr

    elif os.path.exists(pkl_path):
        print(f"[✓] Loading pickle dataset from {pkl_path}")
        with open(pkl_path, "rb") as f:
            data = pickle.load(f, encoding="latin1")
        # data is dict: {(modulation, snr): array of shape (N,2,128)}
        X_list, Y_list, snr_list = [], [], []
        classes = sorted(set(k[0] for k in data.keys()))
        label_map = {c: i for i, c in enumerate(classes)}
        for (mod, snr_val), signals in data.items():
            X_list.append(signals)
            Y_list.extend([label_map[mod]] * len(signals))
            snr_list.extend([snr_val] * len(signals))
        X   = np.vstack(X_list).transpose(0, 2, 1)  # → (N, 128, 2)
        Y   = np.array(Y_list)
        snr = np.array(snr_list)
        print(f"    Classes : {classes}")
        print(f"    X shape : {X.shape}")
        return X, Y, snr, classes

    else:
        raise FileNotFoundError(
            "Dataset not found. On Kaggle add the RadioML 2018.01A dataset, "
            "or place dataset.pkl in the data/ folder."
        )

# ─────────────────────────────────────────
# 2. PREPROCESS
# ─────────────────────────────────────────

def preprocess(X, Y, snr, is_onehot=True):
    """Normalise signals and encode labels."""

    # Normalise each sample to [-1, 1]
    max_vals = np.max(np.abs(X), axis=(1, 2), keepdims=True) + 1e-8
    X = X / max_vals

    if is_onehot:
        # Y is already one-hot (HDF5 format)
        num_classes = Y.shape[1]
        labels_int  = np.argmax(Y, axis=1)
    else:
        # Y is integer-encoded (pickle format)
        num_classes = len(np.unique(Y))
        labels_int  = Y
        Y           = to_categorical(Y, num_classes)

    print(f"[✓] Preprocessing done | X: {X.shape} | Classes: {num_classes}")
    return X, Y, labels_int, num_classes

# ─────────────────────────────────────────
# 3. BUILD CNN MODEL
# ─────────────────────────────────────────

def build_cnn(input_shape, num_classes):
    """
    1D-CNN for IQ signal modulation classification.
    Input shape: (timesteps, 2)  — I and Q channels
    """
    model = Sequential([
        # Block 1
        Conv1D(64, kernel_size=3, activation="relu",
               padding="same", input_shape=input_shape),
        BatchNormalization(),
        MaxPooling1D(pool_size=2),
        Dropout(0.25),

        # Block 2
        Conv1D(128, kernel_size=3, activation="relu", padding="same"),
        BatchNormalization(),
        MaxPooling1D(pool_size=2),
        Dropout(0.25),

        # Block 3
        Conv1D(256, kernel_size=3, activation="relu", padding="same"),
        BatchNormalization(),
        MaxPooling1D(pool_size=2),
        Dropout(0.3),

        # Classification head
        Flatten(),
        Dense(512, activation="relu"),
        Dropout(0.5),
        Dense(128, activation="relu"),
        Dropout(0.3),
        Dense(num_classes, activation="softmax"),
    ])

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="categorical_crossentropy",
        metrics=["accuracy"],
    )
    model.summary()
    return model

# ─────────────────────────────────────────
# 4. TRAIN
# ─────────────────────────────────────────

def train(model, X_train, Y_train, X_val, Y_val):
    os.makedirs("model", exist_ok=True)

    callbacks = [
        EarlyStopping(patience=5, restore_best_weights=True, verbose=1),
        ModelCheckpoint("model/model.h5", save_best_only=True, verbose=1),
    ]

    history = model.fit(
        X_train, Y_train,
        validation_data=(X_val, Y_val),
        epochs=30,
        batch_size=256,
        callbacks=callbacks,
        verbose=1,
    )
    print("[✓] Training complete. Best model saved to model/model.h5")
    return history

# ─────────────────────────────────────────
# 5. VISUALISE RESULTS
# ─────────────────────────────────────────

def plot_training(history):
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.patch.set_facecolor("#0d1117")
    for ax in axes:
        ax.set_facecolor("#161b22")
        ax.tick_params(colors="#c9d1d9")
        ax.xaxis.label.set_color("#c9d1d9")
        ax.yaxis.label.set_color("#c9d1d9")
        ax.title.set_color("#58a6ff")
        for spine in ax.spines.values():
            spine.set_edgecolor("#30363d")

    # Accuracy
    axes[0].plot(history.history["accuracy"],     color="#58a6ff", lw=2, label="Train")
    axes[0].plot(history.history["val_accuracy"], color="#3fb950", lw=2, label="Val")
    axes[0].set_title("Accuracy vs Epoch")
    axes[0].set_xlabel("Epoch"); axes[0].set_ylabel("Accuracy")
    axes[0].legend(facecolor="#21262d", labelcolor="#c9d1d9")

    # Loss
    axes[1].plot(history.history["loss"],     color="#f85149", lw=2, label="Train")
    axes[1].plot(history.history["val_loss"], color="#d29922", lw=2, label="Val")
    axes[1].set_title("Loss vs Epoch")
    axes[1].set_xlabel("Epoch"); axes[1].set_ylabel("Loss")
    axes[1].legend(facecolor="#21262d", labelcolor="#c9d1d9")

    plt.tight_layout()
    plt.savefig("model/training_curves.png", dpi=150, bbox_inches="tight",
                facecolor="#0d1117")
    plt.show()
    print("[✓] Saved training_curves.png")


def plot_confusion_matrix(model, X_test, Y_test, class_names):
    y_pred = np.argmax(model.predict(X_test, batch_size=256, verbose=0), axis=1)
    y_true = np.argmax(Y_test, axis=1)
    cm = confusion_matrix(y_true, y_pred)
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)

    fig, ax = plt.subplots(figsize=(14, 11))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#0d1117")

    sns.heatmap(cm_norm, annot=True, fmt=".2f", cmap="Blues",
                xticklabels=class_names, yticklabels=class_names,
                ax=ax, linewidths=0.5, linecolor="#21262d",
                cbar_kws={"shrink": 0.8})

    ax.set_title("Confusion Matrix (Normalised)", color="#58a6ff", fontsize=16)
    ax.set_xlabel("Predicted", color="#c9d1d9")
    ax.set_ylabel("True",      color="#c9d1d9")
    ax.tick_params(colors="#c9d1d9", labelsize=8)
    plt.tight_layout()
    plt.savefig("model/confusion_matrix.png", dpi=150, bbox_inches="tight",
                facecolor="#0d1117")
    plt.show()
    print("[✓] Saved confusion_matrix.png")
    print("\nClassification Report:\n")
    print(classification_report(y_true, y_pred, target_names=class_names))


# ─────────────────────────────────────────
# 6. SAVE LABEL MAPPING
# ─────────────────────────────────────────

def save_labels(class_names):
    os.makedirs("data", exist_ok=True)
    with open("data/labels.pkl", "wb") as f:
        pickle.dump(class_names, f)
    print(f"[✓] Labels saved → data/labels.pkl : {class_names}")


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Signal Intelligence — CNN Training Pipeline")
    print("=" * 60)

    # --- Load ---
    result = load_dataset()
    if len(result) == 3:
        X, Y, snr = result
        # HDF5: generate class names from index (RadioML 2018 has 24 classes)
        class_names = [
            "OOK","4ASK","8ASK","BPSK","QPSK","8PSK","16PSK","32PSK",
            "16APSK","32APSK","64APSK","128APSK","16QAM","32QAM","64QAM",
            "128QAM","256QAM","AM-SSB-WC","AM-SSB-SC","AM-DSB-WC",
            "AM-DSB-SC","FM","GMSK","OQPSK"
        ]
        is_onehot = True
    else:
        X, Y, snr, class_names = result
        is_onehot = False

    # --- Preprocess ---
    X, Y, labels_int, num_classes = preprocess(X, Y, snr, is_onehot=is_onehot)

    # Subsample for faster training on free GPU (remove for full training)
    SAMPLE = 100_000
    if len(X) > SAMPLE:
        idx = np.random.choice(len(X), SAMPLE, replace=False)
        X, Y, labels_int = X[idx], Y[idx], labels_int[idx]
        print(f"[!] Subsampled to {SAMPLE} samples for speed")

    # --- Split ---
    X_train, X_test, Y_train, Y_test = train_test_split(
        X, Y, test_size=0.2, random_state=42, stratify=labels_int
    )
    X_train, X_val, Y_train, Y_val = train_test_split(
        X_train, Y_train, test_size=0.1, random_state=42
    )
    print(f"[✓] Split → Train:{len(X_train)} | Val:{len(X_val)} | Test:{len(X_test)}")

    # --- Build & Train ---
    model = build_cnn(input_shape=X_train.shape[1:], num_classes=num_classes)
    history = train(model, X_train, Y_train, X_val, Y_val)

    # --- Evaluate ---
    loss, acc = model.evaluate(X_test, Y_test, batch_size=256, verbose=0)
    print(f"\n[✓] Test Accuracy : {acc*100:.2f}%")
    print(f"[✓] Test Loss     : {loss:.4f}")

    # --- Plots ---
    plot_training(history)
    plot_confusion_matrix(model, X_test, Y_test, class_names)

    # --- Save labels ---
    save_labels(class_names)

    print("\n[✓] All done! Download model/model.h5 and data/labels.pkl to your local machine.")
