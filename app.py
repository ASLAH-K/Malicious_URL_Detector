from flask import Flask, request, render_template
import joblib
import pandas as pd
import numpy as np
from scipy.stats import entropy
import os

app = Flask(__name__, template_folder='templates')

# Load the saved model
model_path = os.path.join(os.path.dirname(__file__), 'random_forest_model.pkl')
model = joblib.load(r"C:\Users\mhdas\Desktop\Minor Project Sem 7\random_forest_model.pkl")

# Copy your existing feature extraction functions and lists
suspicious_keywords = [
    "login", "secure", "account", "update", "verify", "password",
    "confirm", "alert", "notification", "invoice", "payment",
    "claim", "reward", "bonus", "urgent", "click", "free", "offer",
    "win", "order", "gift", "support", "contact", "survey", "activate"
]

shortened_domains = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd",
    "buff.ly", "adf.ly", "ow.ly", "shorte.st", "lc.chat",
    "soo.gd", "qr.ae", "v.gd", "rb.gy", "cutt.ly", "po.st"
]

def calculate_entropy(url):
    prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
    return entropy(prob, base=2)

def extract_lexical_features(url):
    url_lower = url.lower()
    contains_suspicious_words = int(any(keyword in url_lower for keyword in suspicious_keywords))
    url_entropy = calculate_entropy(url) if contains_suspicious_words else 0

    features = {
        "url_length": len(url),
        "num_dots": url.count('.'),
        "num_slashes": url.count('/'),
        "num_digits": sum(c.isdigit() for c in url),
        "num_hyphens": url.count('-'),
        "num_special_chars": sum(url.count(char) for char in ['-', '_', '=', '?', '&']),
        "subdomain_count": url.count('.') - 1,
        "https_present": int(url.startswith("https")),
        "num_tokens": len(url.split('/')),
        "digit_to_char_ratio": sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        "contains_suspicious_words": contains_suspicious_words,
        "url_entropy": url_entropy,
        "is_shortened_url": int(any(short_domain in url_lower for short_domain in shortened_domains)),
        "has_executable_extension": int(url_lower.endswith(('.exe', '.zip', '.scr', '.bat', '.dat', '.vbs')))
    }
    
    # Add the combined features
    features['https_subdomain'] = features['https_present'] * 0.001 + features['subdomain_count']
    features['https_num_dots'] = features['https_present'] * 0.001 + features['num_dots']
    features['https_num_digits'] = features['https_present'] * 0.001 + features['num_digits']
    
    # Remove https_present as per your model
    del features['https_present']
    
    return pd.DataFrame([features])

def calculate_custom_score(features):
    # Define feature scaling ranges
    scaling_ranges = {
        "url_length": 200,  # Adjusted range
        "num_dots": 10,
        "num_slashes": 15,
        "num_digits": 30,
        "num_hyphens": 10,
        "num_special_chars": 20,
        "subdomain_count": 5,
        "num_tokens": 20,
        "digit_to_char_ratio": 1,
        "contains_suspicious_words": 1,
        "url_entropy": 10,
        "is_shortened_url": 1,
        "has_executable_extension": 1,
        "https_subdomain": 5,
        "https_num_digits": 30,
        "https_num_dots": 10
    }
    
    # Define feature weights based on importance
    feature_weights = {
        "url_length": 0.25,  # Higher weight for longer URLs
        "num_dots": 0.15,    # More dots can indicate risk
        "num_slashes": 0.15,  # More slashes can indicate risk
        "num_digits": 0.10,   # More digits can indicate risk
        "num_hyphens": 0.10,  # More hyphens can indicate risk
        "num_special_chars": 0.15,  # More special characters can indicate risk
        "subdomain_count": 0.10,     # More subdomains can indicate risk
        "num_tokens": 0.05,           # More tokens can indicate risk
        "digit_to_char_ratio": 0.05,  # Ratio of digits to characters
        "contains_suspicious_words": 0.50,  # High weight for suspicious words
        "url_entropy": 0.20,         # Higher entropy can indicate risk
        "is_shortened_url": 0.20,    # Shortened URLs can indicate risk
        "has_executable_extension": 0.30,  # Executable extensions are risky
        "https_subdomain": 0.10,     # HTTPS subdomains can be risky
        "https_num_digits": 0.05,
        "https_num_dots": 0.05
    }
    
    # Calculate score
    score = sum(
        min(features[feature] / scaling_ranges[feature], 1) * weight 
        for feature, weight in feature_weights.items()
    )
    
    # Normalize score to a scale of 0 to 1
    normalized_score = score / sum(feature_weights.values())
    
    return normalized_score

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        try:
            url = request.form.get('url', '')
            if not url:
                return render_template('index.html', error="Please enter a URL")

            # Extract features
            features = extract_lexical_features(url)
            
            # Get model prediction and probability
            prediction = model.predict(features)[0]
            probability = model.predict_proba(features)[0][1]
            
            # Calculate custom score
            custom_score = calculate_custom_score(features.iloc[0])
            
            # Determine risk categories
            prob_risk_category = "Low Risk" if probability < 0.3 else "Medium Risk" if probability < 0.7 else "High Risk"
            custom_risk_category = "Low Risk" if custom_score < 0.3 else "Medium Risk" if custom_score < 0.7 else "High Risk"
            
            result = {
                'prediction': 'Malicious' if prediction == 1 else 'Benign',
                'probability': f"{probability:.3f}",  # Format to 3 decimal places
                'prob_risk_category': prob_risk_category,
                'custom_score': f"{custom_score:.3f}",  # Format to 3 decimal places
                'custom_risk_category': custom_risk_category
            }
            
            return render_template('index.html', result=result, url=url)
            
        except Exception as e:
            return render_template('index.html', error=f"Error processing URL: {str(e)}")
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)