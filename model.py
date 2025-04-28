import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE
import joblib

# Load CSV, dataset called pre-processed
#https://www.kaggle.com/datasets/engraqeel/iot23preprocesseddata?select=iot23_combined_new.csv
df = pd.read_csv('iot23_combined_new.csv', low_memory=False)

# columns selection
columns_needed = [
    'id.orig_p', 'id.resp_p', 'proto', 'duration', 
    'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'label'
]
df = df[columns_needed]

# Replace '-' with 0 or NaN (choose strategy)
# check with 0
df.replace('-', 0, inplace=True)
# # check with Nan
# df.replace('-', np.nan, inplace=True)

# convert columns explicitly to numeric (float)
numeric_columns = ['id.orig_p', 'id.resp_p', 'duration', 'orig_bytes', 
                   'resp_bytes', 'orig_pkts', 'resp_pkts']

for col in numeric_columns:
    df[col] = pd.to_numeric(df[col], errors='coerce')

# handle missing values (fill NaNs with 0), need to change this too
df.fillna(0, inplace=True)


encoder = LabelEncoder()
df['proto'] = encoder.fit_transform(df['proto'])


df['label'] = df['label'].map({'Benign': 1}).fillna(0)

# check final types
print(df.dtypes)

X = df.drop('label', axis=1)
y = df['label']

# SMOTE balancing, v imp in this case
X_resampled, y_resampled = SMOTE(random_state=42).fit_resample(X, y)

# train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X_resampled, y_resampled, test_size=0.3, random_state=42, stratify=y_resampled
)

# train Random Forest model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# evaluation
y_pred = rf_model.predict(X_test)
print("Classification Report:\n", classification_report(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# save trained model
joblib.dump((rf_model, encoder), 'ids_rf_model.pkl')

print("\n Model trained and saved successfully.")
