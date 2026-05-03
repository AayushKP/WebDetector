import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

class PreClassifier:
    def __init__(self, train_path, test_path):
        self.train_path = train_path
        self.test_path = test_path

    def load_data(self):
        train_df = pd.read_csv(self.train_path)
        test_df = pd.read_csv(self.test_path)

        train_df = train_df.select_dtypes(include=["number"])
        test_df = test_df.select_dtypes(include=["number"])

        self.X_train = train_df.drop(columns=["label"])
        self.y_train = train_df["label"]

        self.X_test = test_df.drop(columns=["label"])
        self.y_test = test_df["label"]

    def train(self):
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42
        )

        self.model.fit(self.X_train, self.y_train)

        #save features names here
        joblib.dump(self.X_train.columns.tolist(), "./TrainedModels/PreClassifier/new_selected_feature_2.pkl")

    def save_model(self, path="pre_classifier.pkl"):
        joblib.dump(self.model, path)
        print(f"Pre-classifier saved at {path}")

    def generate_semantic_features(self, X_hat_train_path, X_hat_test_path):
        train_prob = self.model.predict_proba(self.X_train)
        test_prob = self.model.predict_proba(self.X_test)

        cols = ["prob_benign", "prob_phishing", "prob_defacement", "prob_malware"]

        pd.DataFrame(train_prob, columns=cols).assign(label=self.y_train).to_csv(X_hat_train_path, index=False)
        pd.DataFrame(test_prob, columns=cols).assign(label=self.y_test).to_csv(X_hat_test_path, index=False)