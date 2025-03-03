import pandas as pd
import pickle
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
# Save the trained models using joblib
detector.save_models('phishing_detector.joblib')

# Also save using pickle
print("\nSaving model as pickle file...")
try:
    models = {
        'word2vec': detector.word2vec_model,
        'classifier': detector.classifier,
        'label_encoder': detector.label_encoder,
        'tld_encoder': detector.tld_encoder
    }
    with open('phishing_detector.pkl', 'wb') as f:
        pickle.dump(models, f)
    print("Model successfully saved as pickle file!")
except Exception as e:
    print(f"Error saving pickle file: {str(e)}")

print("Model training and saving completed!")