import pandas as pd
from sklearn.model_selection import train_test_split
from phishing_detector import PhishingURLDetector

print("Loading dataset...")
df = pd.read_csv('url.csv')
print(f"Dataset shape: {df.shape}")

# Initialize the detector
detector = PhishingURLDetector()

print("\nTraining model...")
# Train using the dataset
detector.train(df['URL'], df['label'])

print("\nSaving trained models...")
# Save the trained models
detector.save_models('phishing_detector.joblib')

print("Model training and saving completed!")
