"""
TON_IoT IDS Model Training Script
Trains a Random Forest classifier for IoT intrusion detection
"""

import json
import os
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
from sklearn.ensemble import RandomForestClassifier

RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)
sns.set_style('whitegrid')

# Paths
DATA_PATH = 'data/ton_iot/train_test_network.csv'
MODEL_DIR = 'models/ton_iot'
os.makedirs(MODEL_DIR, exist_ok=True)

print("="*60)
print("TON_IoT IDS Model Training")
print("="*60)

# Step 1: Load Data
print("\n[1/6] Loading dataset...")
df = pd.read_csv(DATA_PATH)
print(f"Loaded: {DATA_PATH}")
print(f"Shape: {df.shape}")

# Step 2: Define Features and Target
print("\n[2/6] Preparing features and target...")
if 'type' in df.columns:
    target_col = 'type'
elif 'label' in df.columns:
    target_col = 'label'
else:
    raise ValueError('No target column found. Expected one of: type, label')

print(f"Target column: {target_col}")
print(f"\nTarget distribution:")
print(df[target_col].value_counts().head(20))

# Remove leakage/ID columns
leakage_or_id_cols = ['ts', 'pkSeqID', 'seq', 'attack']
remove_cols = [c for c in leakage_or_id_cols if c in df.columns and c != target_col]

X = df.drop(columns=[target_col] + remove_cols)
y = df[target_col].astype(str)

print(f"\nRemoved columns: {remove_cols}")
print(f"Feature matrix shape: {X.shape}")
print(f"Target shape: {y.shape}")

# Step 3: Handle Missing Values and Encode Categories
print("\n[3/6] Setting up preprocessing...")
numeric_features = X.select_dtypes(include=[np.number]).columns.tolist()
categorical_features = X.select_dtypes(exclude=[np.number]).columns.tolist()

numeric_transformer = Pipeline([
    ('imputer', SimpleImputer(strategy='median')),
])

categorical_transformer = Pipeline([
    ('imputer', SimpleImputer(strategy='most_frequent')),
    ('onehot', OneHotEncoder(handle_unknown='ignore')),
])

preprocess = ColumnTransformer([
    ('num', numeric_transformer, numeric_features),
    ('cat', categorical_transformer, categorical_features),
])

print(f"Numeric features: {len(numeric_features)}")
print(f"Categorical features: {len(categorical_features)}")

# Step 4: Split Data
print("\n[4/6] Splitting data into train/test sets...")
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=RANDOM_STATE,
    stratify=y,
)

print(f"X_train: {X_train.shape} | X_test: {X_test.shape}")
print(f"Number of classes: {y_train.nunique()}")

# Step 5: Train Model
print("\n[5/6] Training Random Forest model...")
pipeline = Pipeline([
    ('preprocess', preprocess),
    ('model', RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        class_weight='balanced',
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )),
])

print("Fitting model (this may take a few minutes)...")
pipeline.fit(X_train, y_train)
print("Model training complete!")

# Step 6: Evaluate
print("\n[6/6] Evaluating model...")
y_pred = pipeline.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision, recall, f1, support = precision_recall_fscore_support(
    y_test, y_pred, average='weighted'
)

print(f"\n{'='*60}")
print(f"MODEL PERFORMANCE METRICS")
print(f"{'='*60}")
print(f"Accuracy:  {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1-Score:  {f1:.4f}")
print(f"{'='*60}")

print("\nDetailed Classification Report:")
print(classification_report(y_test, y_pred))

# Save model artifacts
print("\nSaving model artifacts...")
joblib.dump(pipeline, os.path.join(MODEL_DIR, 'ton_iot_model_pipeline.joblib'))
print(f"✓ Model pipeline saved to: {MODEL_DIR}/ton_iot_model_pipeline.joblib")

# Save label encoder
label_encoder = LabelEncoder()
label_encoder.fit(y)
joblib.dump(label_encoder, os.path.join(MODEL_DIR, 'ton_iot_label_encoder.joblib'))
print(f"✓ Label encoder saved to: {MODEL_DIR}/ton_iot_label_encoder.joblib")

# Save metadata
metadata = {
    'target_column': target_col,
    'removed_columns': remove_cols,
    'numeric_features': numeric_features,
    'categorical_features': categorical_features,
    'classes': list(label_encoder.classes_),
    'train_size': len(X_train),
    'test_size': len(X_test),
    'accuracy': accuracy,
    'precision': precision,
    'recall': recall,
    'f1_score': f1,
}

with open(os.path.join(MODEL_DIR, 'ton_iot_metadata.json'), 'w') as f:
    json.dump(metadata, f, indent=2)
print(f"✓ Metadata saved to: {MODEL_DIR}/ton_iot_metadata.json")

print("\n" + "="*60)
print("TRAINING COMPLETE!")
print("="*60)
print(f"\nModel files saved in: {MODEL_DIR}/")
print("You can now use the model for inference!")
