import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

df = pd.read_csv("usb_behavior_dataset.csv")

X = df.drop('label',axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2,random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train,y_train)

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test,predictions)
print(f"Accuracy : {accuracy:.4f}")

joblib.dump(model,'behavModel.joblib')
print("Model saved...")
