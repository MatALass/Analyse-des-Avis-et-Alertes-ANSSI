# Cybersecurity Analysis & AI Game Project

This repository combines **cybersecurity data analysis** with a small **AI-powered game** experiment.

---

## 📂 Project Structure
- `Analyse des Avis et Alertes ANSSI...pptx` → Presentation of ANSSI advisories & CVE analysis  
- `Analyse TD_final.ipynb / .html` → Jupyter notebook for data exploration & analysis  
- `anssi_cve_data_reduced.csv` → Dataset of reduced ANSSI/CVE information  
- `details_100.xlsx` → Excel dataset for vulnerability details  
- `df_create.py` → Script for dataset creation/processing  
- `main.py` → Connect Four variant with AI (Minimax + heuristics)  
- `B.py` → Additional Python utility/game logic  
- `data_pour_TD_final.zip` / `Compressed Data.zip` → Compressed datasets for analysis  
- `.idea/`, `.venv/` → Project environment and IDE configs  

---

## 🚀 Features
- **Cybersecurity data analysis**:
  - CVE enrichment
  - ANSSI advisories parsing
  - Interactive exploration in Jupyter
- **AI-powered game**:
  - Connect Four variant (12x6 board)
  - Minimax algorithm with alpha-beta pruning & heuristics
  - Human vs AI console gameplay

---

## 🛠️ Requirements
- Python 3.8+
- Libraries: `pandas`, `numpy`, `matplotlib` (for analysis), standard library (for game)

---

## ▶️ Usage
### 1. Cybersecurity Analysis
Open the notebook:
```bash
jupyter notebook "Analyse TD_final.ipynb"
