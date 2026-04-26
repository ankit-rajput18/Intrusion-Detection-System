"""
Test the trained IDS model with sample predictions
"""

import joblib
import pandas as pd
import numpy as np

# Load the trained model
print("Loading trained model...")
pipeline = joblib.load('models/ton_iot/ton_iot_model_pipeline.joblib')
label_encoder = joblib.load('models/ton_iot/ton_iot_label_encoder.joblib')

print("Model loaded successfully!\n")

# Load some test data
print("Loading test data...")
df = pd.read_csv('data/ton_iot/train_test_network.csv')

# Remove leakage/ID columns (same as training)
leakage_or_id_cols = ['ts', 'pkSeqID', 'seq', 'attack']
target_col = 'type'
remove_cols = [c for c in leakage_or_id_cols if c in df.columns and c != target_col]

X = df.drop(columns=[target_col] + remove_cols)
y = df[target_col].astype(str)

print(f"Dataset loaded: {X.shape[0]} samples\n")

# Test on random samples
print("="*70)
print("TESTING MODEL PREDICTIONS")
print("="*70)

np.random.seed(42)
test_indices = np.random.choice(len(X), size=10, replace=False)

for i, idx in enumerate(test_indices, 1):
    # Get single sample
    sample = X.iloc[idx:idx+1]
    actual_label = y.iloc[idx]
    
    # Predict
    predicted_label = pipeline.predict(sample)[0]
    
    # Check if correct
    status = "✓ CORRECT" if actual_label == predicted_label else "✗ WRONG"
    
    print(f"\nSample {i}: {status}")
    print(f"  Actual:     {actual_label}")
    print(f"  Predicted:  {predicted_label}")

# Overall accuracy on full dataset
print("\n" + "="*70)
print("CALCULATING OVERALL ACCURACY...")
print("="*70)

y_pred = pipeline.predict(X)
accuracy = (y_pred == y).mean() * 100

print(f"\nOverall Accuracy: {accuracy:.2f}%")
print(f"Total samples tested: {len(X)}")
print(f"Correct predictions: {int((y_pred == y).sum())}")
print(f"Wrong predictions: {int((y_pred != y).sum())}")

# Per-class accuracy
print("\n" + "="*70)
print("PER-CLASS ACCURACY:")
print("="*70)

unique_classes = y.unique()
for cls in sorted(unique_classes):
    mask = (y == cls)
    if mask.sum() > 0:
        class_accuracy = ((y_pred[mask] == y[mask]).sum() / mask.sum()) * 100
        print(f"{cls:15s}: {class_accuracy:6.2f}% ({mask.sum():5d} samples)")

print("\n" + "="*70)
print("MODEL TEST COMPLETE!")
print("="*70)
