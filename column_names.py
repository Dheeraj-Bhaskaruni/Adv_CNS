import pandas as pd

df = pd.read_csv('iot23_combined_new.csv',low_memory=False)

print(df.shape)

# checking col names
print(df.columns.tolist())

df.info()
