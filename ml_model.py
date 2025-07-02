import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

def load_data(csv_file):
    df = pd.read_csv(csv_file)
    df = df[["Packet Size", "Local Label"]]
    df["Label"] = df["Local Label"].map({"Normal": 0, "Anomalous": 1})
    X = df[["Packet Size"]]
    y = df["Label"]
    return X, y

from imblearn.over_sampling import RandomOverSampler, SMOTE
from collections import Counter

def train_model(csv_file, model_path="model.pkl"):
    X, y = load_data(csv_file)
    counts = Counter(y)
    minority = counts[1]  # 1 = Anomalous

    if minority < 2:
        print(f"⚠️  Only {minority} anomalous sample(s) found – using RandomOverSampler.")
        sampler = RandomOverSampler(random_state=42)
    else:
        print(f"ℹ️  {minority} anomalous samples – using SMOTE.")
        sampler = SMOTE(random_state=42)

    X_res, y_res = sampler.fit_resample(X, y)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_res, y_res)

    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    print(f"✅ Model balanced and saved to '{model_path}'.")

def predict_packet(size, model_path="model.pkl"):
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    pred = model.predict([[size]])[0]
    return "Anomalous" if pred == 1 else "Normal"
