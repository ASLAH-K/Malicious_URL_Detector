
# AI-Driven Malicious URL Detection and Risk Scoring System 🔐

A lightweight and interpretable machine learning-based web application for classifying URLs as **malicious or benign** and assigning risk scores using lexical features. Built using Flask and Random Forest classifier.

---

## 🚀 Features

- **Real-time URL classification** via web interface
- Dual risk scoring: **probability-based** and **custom-weighted**
- Uses only lexical features (no external APIs or DNS lookups)
- Lightweight and scalable system
- Achieves **98.84% accuracy** using balanced dataset of 632,508 URLs

---

## 📁 Project Structure

```
├── app.py                  # Flask backend
├── random_forest_model.pkl # Trained ML model
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # HTML frontend
├── notebooks/
│   └── project1_Randomforest.ipynb
├── dataset/
│   └── balanced_urls.csv    #The original dataset used to train the model
├── report/
│   └── Project_report.docx
```

---

## ⚙️ How It Works

1. **User submits a URL**
2. **Lexical features** are extracted:
   - URL length, dots, slashes, digits, suspicious keywords, entropy, etc.
3. Pre-trained **Random Forest model** predicts:
   - Class (`Malicious` or `Benign`)
   - Probability-based risk score
   - Custom-weighted risk score
4. **Results displayed** on the web UI

---

## 🧠 ML Model Details

- **Algorithm**: Random Forest
- **Dataset**: 632,508 labeled URLs (balanced benign/malicious)
- **Accuracy**: 98.84%
- **Tools**: Python, Scikit-learn, Pandas, NumPy, Flask

---

## 🔧 Setup Instructions

1. Clone the repo using GitHub Desktop or Git:
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Add your `random_forest_model.pkl` in the project root.
4. Run the app:
   ```bash
   python app.py
   ```
5. Open in browser:
   ```
   http://127.0.0.1:5000
   ```

---

## 📌 Future Enhancements

- Real-time threat intelligence integration
- Deep learning models (e.g., LSTM for dynamic behavior)
- SHAP/LIME explainability
- Browser plugin
- Cloud deployment (AWS/Azure)

---

## 👨‍💻 Developed by

**Muhammed Aslah K**  
B.Tech-M.Tech Integrated Cybersecurity  
National Forensic Sciences University

---

## 📄 License

This project is for academic and research purposes.
