"""
Python3 script to train Random Forest and StandardScaler on combined.csv,
then save the models as joblib files for use in the controller.
Also prints accuracy on a 10% test split.
"""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# Đọc dữ liệu
df = pd.read_csv('combined.csv', header=None)

# Xóa cột thứ 8 (index = 7)
df = df.drop(df.columns[7], axis=1)

# Tách features và labels
X = df.iloc[:, :-1].values  # all columns except last
y = df.iloc[:, -1].values   # last column as label

# Chia train/test với 10% test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.10, random_state=42)

# Chuẩn hóa dữ liệu
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Huấn luyện mô hình Random Forest
clf = RandomForestClassifier(n_estimators=100, criterion='entropy', random_state=0)
clf.fit(X_train_scaled, y_train)

# Dự đoán và đánh giá accuracy
y_pred = clf.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)

# Lưu model và scaler
tjob_path = 'rf_model_1.joblib'
scaler_path = 'rf_scaler_1.joblib'
joblib.dump(clf, tjob_path)
joblib.dump(scaler, scaler_path)

# In kết quả
print("Training completed.")
print(f"Accuracy on 10% test split: {accuracy * 100:.2f}%")
print(f"Model saved to: {tjob_path}")
print(f"Scaler saved to: {scaler_path}")

