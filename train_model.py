import pandas as pd
import numpy as np
import re
import pickle
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

def extract_features(url):
    features = []
    # 1. URL length
    features.append(len(url))
    # 2. Has IP address
    features.append(1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0)
    # 3. Has @ symbol
    features.append(1 if '@' in url else 0)
    # 4. Count of dots
    features.append(url.count('.'))
    # 5. Count of hyphens
    features.append(url.count('-'))
    # 6. Has HTTPS
    features.append(1 if url.startswith('https') else 0)
    # 7. Count of digits
    features.append(sum(c.isdigit() for c in url))
    # 8. Suspicious words
    suspicious = ['login','verify','secure','account','update','bank','paypal','signin','confirm','alert']
    features.append(sum(1 for w in suspicious if w in url.lower()))
    # 9. URL shortener
    shorteners = ['bit.ly','tinyurl','goo.gl','t.co','ow.ly']
    features.append(1 if any(s in url for s in shorteners) else 0)
    # 10. Suspicious TLD
    bad_tlds = ['.xyz','.tk','.ml','.ga','.cf','.gq']
    features.append(1 if any(url.endswith(t) or t+'/' in url for t in bad_tlds) else 0)
    return features

# Load data
df = pd.read_csv('dataset/phishing.csv')
X = np.array([extract_features(u) for u in df['url']])
y = df['label'].values

# Split & train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Accuracy
pred = model.predict(X_test)
print(f"✅ Accuracy: {accuracy_score(y_test, pred)*100:.2f}%")

# Save
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
print("✅ Model saved as model.pkl")