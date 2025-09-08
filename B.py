# === Version Locale du Projet ANSSI (Lecture fichiers) ===

import os
import json
import pandas as pd
import re
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

BASE_DIR = "Data_pour_td_final"

# === Étape 1 : Lister les bulletins (avis + alertes) ===
def list_bulletin_files():
    alertes_path = os.path.join(BASE_DIR, "alertes")
    avis_path = os.path.join(BASE_DIR, "Avis")
    files = []
    for path in [alertes_path, avis_path]:
        for filename in os.listdir(path):
            if filename.endswith(".json"):
                files.append({
                    "type": "Alerte" if "alertes" in path else "Avis",
                    "filepath": os.path.join(path, filename)
                })
    return files

# === Étape 2 : Extraction des CVE depuis les bulletins JSON ===
def extract_cve_from_local_bulletin(filepath):
    with open(filepath, encoding='utf-8') as f:
        data = json.load(f)
    cves = [cve['name'] for cve in data.get('cves', [])]
    return cves, data

# === Étape 3 : Enrichissement local MITRE ===
def enrich_cve_mitre_local(cve_id):
    path = os.path.join(BASE_DIR, "mitre", f"{cve_id}.json")
    if not os.path.exists(path):
        return "", None, None, "Non disponible", "Non disponible", []
    with open(path, encoding='utf-8') as f:
        data = json.load(f)

    if 'containers' not in data or 'cna' not in data['containers']:
        # Données non conformes, on retourne des valeurs par défaut
        return "", None, None, "Non disponible", "Non disponible", []

    container = data['containers']['cna']
    description = container['descriptions'][0]['value'] if container.get('descriptions') else ""
    metrics = container.get("metrics", [{}])[0]
    cvss_score = metrics.get("cvssV3_1", {}).get("baseScore", None)
    severity = metrics.get("cvssV3_1", {}).get("baseSeverity", None)
    problemtype = container.get("problemTypes", [{}])[0]
    cwe = problemtype.get("descriptions", [{}])[0].get("cweId", "Non disponible")
    cwe_desc = problemtype.get("descriptions", [{}])[0].get("description", "Non disponible")
    affected = container.get("affected", [])
    return description, cvss_score, severity, cwe, cwe_desc, affected


# === Étape 4 : Enrichissement local EPSS ===
def enrich_cve_epss_local(cve_id):
    path = os.path.join(BASE_DIR, "first", f"{cve_id}.json")
    if not os.path.exists(path):
        return 0
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    epss_data = data.get("data", [])
    if not epss_data:  # Liste vide
        return 0
    return epss_data[0].get("epss", 0)


# === Étape 5 : Construire le DataFrame ===
def build_dataframe_local():
    files = list_bulletin_files()
    print(f"{len(files)} bulletins trouvés")
    all_data = []
    for bulletin in files:
        cves, data = extract_cve_from_local_bulletin(bulletin["filepath"])
        bulletin_id = data.get("id", "N/A")
        title = data.get("title", "")
        date = data.get("published", "")
        for cve_id in cves:
            desc, cvss, sev, cwe, cwe_desc, affected = enrich_cve_mitre_local(cve_id)
            epss = enrich_cve_epss_local(cve_id)
            if not affected:
                all_data.append({
                    'ID_ANSSI': bulletin_id,
                    'Titre': title,
                    'Type': bulletin["type"],
                    'Date': date,
                    'CVE': cve_id,
                    'CVSS': cvss,
                    'Severity': sev,
                    'CWE': cwe,
                    'CWE_Description': cwe_desc,
                    'EPSS': epss,
                    'Lien': bulletin["filepath"],
                    'Description': desc,
                    'Vendor': None,
                    'Produit': None,
                    'Versions': None
                })
            for product in affected:
                versions = ''
                if 'versions' in product:
                    versions = ', '.join([v['version'] for v in product['versions'] if v.get('status') == 'affected'])
                all_data.append({
                    'ID_ANSSI': bulletin_id,
                    'Titre': title,
                    'Type': bulletin["type"],
                    'Date': date,
                    'CVE': cve_id,
                    'CVSS': cvss,
                    'Severity': sev,
                    'CWE': cwe,
                    'CWE_Description': cwe_desc,
                    'EPSS': epss,
                    'Lien': bulletin["filepath"],
                    'Description': desc,
                    'Vendor': product.get('vendor', None),
                    'Produit': product.get('product', None),
                    'Versions': versions
                })

    return pd.DataFrame(all_data)

# === Étape 6 : Visualisation simple ===
def plot_cvss_distribution(df):
    if "CVSS" not in df.columns:
        print("Colonne CVSS introuvable.")
        return
    sns.histplot(df["CVSS"].dropna(), bins=10, kde=True)
    plt.title("Distribution des scores CVSS")
    plt.xlabel("Score CVSS")
    plt.ylabel("Nombre de vulnérabilités")
    plt.show()

# === Étape 7 : Machine Learning ===
def ml_modeling(df):
    df_ml = df.dropna(subset=['CVSS', 'EPSS'])
    features = df_ml[['CVSS', 'EPSS']]
    scaler = StandardScaler()
    X = scaler.fit_transform(features)

    kmeans = KMeans(n_clusters=3, random_state=42)
    df_ml = df_ml.copy()
    df_ml['Cluster'] = kmeans.fit_predict(X)

    X_train, X_test, y_train, y_test = train_test_split(X, df_ml['Severity'], test_size=0.3, random_state=42)
    clf = RandomForestClassifier()
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))

# === Main ===
def main():
    df = build_dataframe_local()
    print("Colonnes du DataFrame:", df.columns.tolist())
    print(df.head())
    df.to_csv("cve_enriched_local.csv", index=False)
    plot_cvss_distribution(df)
    ml_modeling(df)

if __name__ == "__main__":
    main()
