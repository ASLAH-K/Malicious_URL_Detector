   # AI-Driven Malicious URL Detection and Risk Scoring System 🔐

I built this project to explore how machine learning can be used to detect malicious URLs **without relying on external threat intelligence, DNS lookups, or third-party APIs**.

The idea was simple: *Can a URL be classified as malicious just by looking at its structure?*

To answer that, I trained a **Random Forest** model using lexical URL features and built a lightweight **Flask web application** that predicts whether a URL is **malicious or benign**, along with two different risk scores.

---

## 🚀 Features

* Detects whether a URL is **Malicious** or **Benign**
* Dual risk scoring:

  * **Probability-based** risk score
  * **Custom weighted** risk score
* Uses only **lexical URL features**
* No external APIs, DNS queries, or online threat feeds required
* Lightweight Flask web interface
* Achieved **98.84% accuracy** on a balanced dataset of **632,508 URLs**

---

## 📸 Screenshots

> *(Screenshots will be added here.)*

* Home page
* Prediction result (Malicious)
* Prediction result (Benign)

---

## 💡 Why I Built This

Most malicious URL detection systems depend on external services such as DNS lookups, WHOIS records, or threat intelligence feeds.

I wanted to understand how far a machine learning model could go by using **only the information available within the URL itself**.

This project helped me learn about:

* Feature engineering
* Machine learning for cybersecurity
* Model evaluation
* Flask application development
* Risk scoring techniques

---

## ⚙️ How It Works

1. A user submits a URL through the web interface.
2. The application extracts lexical features such as:

   * URL length
   * Number of dots
   * Number of slashes
   * Number of digits
   * Special characters
   * URL entropy
   * Suspicious keywords
   * Executable extensions
3. The trained **Random Forest** model predicts whether the URL is malicious or benign.
4. Two risk scores are generated:

   * Probability-based score using the model confidence
   * Custom weighted score based on selected URL characteristics
5. The prediction and risk scores are displayed in the web application.

---

## 🧠 Machine Learning Details

| Property     | Value                         |
| ------------ | ----------------------------- |
| Model        | Random Forest Classifier      |
| Dataset Size | 632,508 URLs                  |
| Dataset Type | Balanced (Benign & Malicious) |
| Accuracy     | **98.84%**                    |
| Precision    | **99.73%**                    |
| Recall       | **97.95%**                    |
| F1 Score     | **98.83%**                    |
| ROC-AUC      | **99.72%**                    |

---

## 🛠️ Tech Stack

* Python
* Flask
* Scikit-learn
* Pandas
* NumPy
* Jupyter Notebook

---

## 📁 Project Structure

```text
├── app.py                      # Flask application
├── random_forest_model.pkl     # Trained Random Forest model
├── requirements.txt            # Project dependencies
├── templates/
│   └── index.html              # Web interface
├── notebooks/
│   └── project1_Randomforest.ipynb
├── dataset/
│   └── balanced_urls.csv       # Training dataset
├── report/
│   └── Project_report.docx
```

---

## 🛠️ Installation

Clone the repository:

```bash
git clone https://github.com/ASLAH-K/Malicious_URL_Detector.git
```

Move into the project directory:

```bash
cd Malicious_URL_Detector
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Place the trained model (`random_forest_model.pkl`) in the project root.

Run the application:

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

---

## 🎯 Example Workflow

```
Input URL
      │
      ▼
Feature Extraction
      │
      ▼
Random Forest Model
      │
      ▼
Prediction
      │
      ├── Benign / Malicious
      ├── Probability Risk Score
      └── Custom Weighted Risk Score
```

---

## 📚 What I Learned

Working on this project gave me hands-on experience with:

* Feature engineering for cybersecurity datasets
* Training and tuning Random Forest models
* Evaluating machine learning models beyond accuracy
* Building a Flask-based web application
* Designing lightweight risk scoring systems
* Deploying a trained ML model for real-time predictions

One interesting challenge was that the `https_present` feature initially dominated the model's importance. I refined the feature engineering process to reduce its influence and encourage the model to learn from a broader set of lexical characteristics.

---

## 🔮 Future Improvements

Some ideas I'd like to explore in future versions:

* Browser extension for real-time URL scanning
* Integration with threat intelligence feeds
* Explainable AI using SHAP or LIME
* Deep learning approaches for comparison
* Docker support
* Cloud deployment (AWS or Azure)

---

## 📄 License

This project was developed for educational and research purposes.
 
