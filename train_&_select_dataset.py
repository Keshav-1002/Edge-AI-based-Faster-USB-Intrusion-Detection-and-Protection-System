import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
import joblib

#load db & div into train & test data
df = pd.read_csv('custom_training_ds.csv')
X = df.drop('malicious',axis=1)
y = df['malicious']
X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2,random_state=42)

#dic of diff models with diff classifiers
models = {  'DecisionTree': DecisionTreeClassifier() ,
            'RandomForest' : RandomForestClassifier() ,
            'LogisticReg' : LogisticRegression(max_iter=1000),
            'SVC': SVC() 
         }

#best model details
best_model = None
best_accuracy = -1
best_name = None

#training all models and find the best one
for name,model in models.items():
    model.fit(X_train,y_train)
    pred = model.predict(X_test)
    acc = accuracy_score(y_test,pred)

    print(f"{name} trained with accuracy of {acc:.4f}")
    
    if(acc>best_accuracy):
        best_accuracy = acc
        best_model = model
        best_name = name


#saving best model
joblib.dump(best_model,'bestAIModel.joblib')
print(f"Best model saved: {best_name} with accuracy of {best_accuracy:.4f}")
