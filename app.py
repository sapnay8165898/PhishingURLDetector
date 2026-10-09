from flask import Flask, render_template, request
import pickle, re, numpy as np

app = Flask(__name__)
model = pickle.load(open('model.pkl', 'rb'))

def extract_features(url):
    f = []
    f.append(len(url))
    f.append(1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0)
    f.append(1 if '@' in url else 0)
    f.append(url.count('.'))
    f.append(url.count('-'))
    f.append(1 if url.startswith('https') else 0)
    f.append(sum(c.isdigit() for c in url))
    suspicious = ['login','verify','secure','account','update','bank','paypal','signin','confirm','alert']
    f.append(sum(1 for w in suspicious if w in url.lower()))
    shorteners = ['bit.ly','tinyurl','goo.gl','t.co','ow.ly']
    f.append(1 if any(s in url for s in shorteners) else 0)
    bad_tlds = ['.xyz','.tk','.ml','.ga','.cf','.gq']
    f.append(1 if any(url.endswith(t) or t+'/' in url for t in bad_tlds) else 0)
    return f

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    features = np.array([extract_features(url)])
    prediction = model.predict(features)[0]
    prob = model.predict_proba(features)[0]
    confidence = round(max(prob)*100, 2)
    result = "⚠️ PHISHING URL DETECTED!" if prediction == 1 else "✅ SAFE URL"
    color = "danger" if prediction == 1 else "success"
    return render_template('result.html', url=url, result=result, confidence=confidence, color=color)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)