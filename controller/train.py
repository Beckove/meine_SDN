#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python3 script to train Random Forest and StandardScaler on dm.csv,
then save the models as joblib files for use in the controller.
"""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib

# 1. Read data from dm.csv (no header)
#    dm.csv should be in current working directory
#    Columns: 0..N-1, where column 7 is IP (drop), last column is label

df = pd.read_csv('vl.csv', header=None)

# 2. Drop the IP address column (index 7)
df = df.drop(df.columns[7], axis=1)

# 3. Separate features and labels
X = df.iloc[:, :-1].values  # all columns except last
y = df.iloc[:, -1].values   # last column as label

# 4. Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 5. Train Random Forest classifier
clf = RandomForestClassifier(n_estimators=100, criterion='entropy', random_state=0)
clf.fit(X_scaled, y)

# 6. Save the trained model and scaler
tjob_path = 'rf_model_1.joblib'
scaler_path = 'rf_scaler_1.joblib'
joblib.dump(clf, tjob_path)
joblib.dump(scaler, scaler_path)

print(f"Training completed.")
print(f"Model saved to: {tjob_path}")
print(f"Scaler saved to: {scaler_path}")

