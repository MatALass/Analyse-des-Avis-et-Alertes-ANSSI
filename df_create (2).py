#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
README : 
    Pour lancer le code, d'abord run la section d'importation, puis run la 
    section suivante (pour version locale), ou celle d'après (version API)
    
    Section locale : s'assurer d'avoir les fichiers de donnéees déposés sur moodle 
    dans le même répertoire que ce code, dans un fichier appelé "data_pour_TD_final"
    Le code s'exécute rapidement, devrait print "Data exportées dans le fichier anssi_local_data_sans_doublons.csv"
    et "Aucun doublon détecté dans le fichier."
    ATTENTION : la console affiche des erreurs, elles sont ignorées mais sont 
    créées car le fichier mitre transmis ne semble pas contenir toutes les CVE
    référencées par les avis et alertes
    
    Section API : remplacer votre@email.com dans les paramètres de update_bulletin_data par l'email ou vous voulez recevoir les alertes'
    Le code prend plus de temps à s'exécuter du aux restrictions de rate limit des API, 
    compter environ 15 minutes en fonction de la machine et des serveurs.
    
    Pour le reste du projet, nous avons utilisé comme base le csv créé par originellement par les API 'anssi_cve_data_reduced.csv'
    La section API en temps réél le récupère comme base mais si inexistant en créé un nouveau

"""

#%% import
import feedparser
import requests
import re
import time
import pandas as pd
from tqdm import tqdm # sert à afficher la progression des API dans la section API
import json
import os
from email.mime.text import MIMEText
import smtplib


#%% LOCAL VERSION

def get_avis(avis_id):
    #récupère les infos d'un fichier avis
    with open(r"data_pour_TD_final/avis/"+avis_id, 'r') as f:
        data=json.load(f)
    return data
def get_alerte(alerte_id):
    #récupère les infos d'un fichier alerte
    with open(r"data_pour_TD_final/alertes/"+alerte_id, 'r') as f:
        data=json.load(f)
    return data

def get_cve_mitre(cve_id):
    #récupère les infos d'un fichier mitre
    with open(r"data_pour_TD_final/mitre/"+cve_id, 'r') as f:
        data=json.load(f)
    return data

def get_cve_first(cve_id):
    #récupère les infos d'un fichier first
    with open(r"data_pour_TD_final/first/"+cve_id, 'r') as f:
        data=json.load(f)
    return data

def build_local_dataframe(avis_path="data_pour_TD_final/avis", alertes_path="data_pour_TD_final/alertes"):
    # gross_data = liste de dicos qui servira à créer un dataframe
    gross_data = []

    # récupère les fichiers avis et alertes, et leur applique la fonction get appropriée
    for folder, get_func, bulletin_type in [
        (avis_path, get_avis, "Avis"),
        (alertes_path, get_alerte, "Alerte")
    ]:
        for file in os.listdir(folder):
            try: 
            # bloc try pour ignorer les potentielles erreurs du au formatage ou à des infos manquantes
                # récupère les infos des différents fichiers alertes et avis
                bulletin = get_func(file)
                # récupère la liste de CVE mentionné par ce bulletin
                cve_list = [cve["name"] for cve in bulletin.get("cves", [])]

                for cve_id in cve_list:
                    try:
                        mitre_data = get_cve_mitre(cve_id)
                        epss_data = get_cve_first(cve_id)
                        
                        # containers créé pour faciliter le code derrière, dico ['containers']['cna'] est souvent accédé
                        containers = mitre_data.get("containers", {}).get("cna", {})
                        description = next((d.get("value") for d in containers.get("descriptions", []) if d.get("lang") == "en"), "Non disponible")

                        # CVSS
                        cvss_score = None
                        severity = "Non disponible"
                        for m in containers.get("metrics", []):
                            for version in ["cvssV3_1", "cvssV3_0"]:
                                if version in m:
                                    cvss_score = m[version].get("baseScore", None)
                                    severity = m[version].get("baseSeverity", "Non disponible")
                                    break
                            if cvss_score is not None:
                                break

                        # CWE
                        problemtype = containers.get("problemTypes", [])
                        cwe_id, cwe_desc = "Non disponible", "Non disponible"
                        if problemtype and "descriptions" in problemtype[0]:
                            descs = problemtype[0]["descriptions"]
                            if descs:
                                cwe_desc = descs[0].get("description", "Non disponible")
                                cwe_id = descs[0].get("cweId", "Non disponible")

                        # Produits
                        for affected in containers.get("affected", []):
                            vendor = affected.get("vendor", "Inconnu")
                            product = affected.get("product", "Inconnu")
                            versions = [v["version"] for v in affected.get("versions", []) if v.get("status") == "affected"]
                            version_str = ", ".join(versions) if versions else "Non spécifié"

                            epss_score = epss_data.get("data", [{}])[0].get("epss", None)

                            gross_data.append({
                                "ID du bulletin": file,
                                "Titre du bulletin": bulletin.get("title", "Non disponible"),
                                "Type de bulletin": bulletin_type,
                                "Date de publication": bulletin.get("revisions", [{}])[0].get("revision_date", None),
                                "Lien du bulletin (ANSSI)": f"https://www.cert.ssi.gouv.fr/{'avis' if bulletin_type=='Avis' else 'alertes'}/{file}",
                                "Identifiant CVE": cve_id,
                                "Score CVSS": cvss_score,
                                "Base Severity": severity,
                                "Type CWE": cwe_id,
                                "Score EPSS": epss_score,
                                "Description": cwe_desc,
                                "Éditeur/Vendor": vendor,
                                "Produit": product,
                                "Versions affectées": version_str
                            })

                    except Exception as e:
                        print(f"Erreur traitement CVE {cve_id} dans {file} : {e}")
                        continue
            except Exception as e:
                print(f"Erreur lecture du fichier {file} : {e}")
                continue

    return pd.DataFrame(gross_data)


def verifier_doublons_csv(path_csv):
    df = pd.read_csv(path_csv)

    # Recherche des doublons exacts (lignes identiques sur toutes les colonnes)
    doublons = df[df.duplicated(keep=False)]

    if doublons.empty:
        print("Aucun doublon détecté dans le fichier.")
    else:
        print(f"⚠️ {len(doublons)} doublon(s) trouvé(s) dans le fichier :")



df = build_local_dataframe()
df_cleaned = df.drop_duplicates()
df_cleaned.to_csv("anssi_local_data_sans_doublons.csv", index=False)
print("Data exportées dans le fichier anssi_local_data_sans_doublons.csv")

verifier_doublons_csv("anssi_local_data_sans_doublons.csv")


#%% API VERSION

# Extraction des bulletins RSS ANSSI
def fetch_anssi_bulletins(feed_url="https://www.cert.ssi.gouv.fr/avis/feed"):
    feed = feedparser.parse(feed_url)
    bulletins = []
    # parcourir les différents avis et alerte trouvés
    for entry in feed.entries:
        # définir si avis ou alerte
        bulletin_type = "Avis" if "/avis/" in entry.link else "Alerte"
        # recupérer id contenu dans le lien
        bulletin_id = entry.link.strip("/").split("/")[-1]
        bulletins.append({
            "bulletin_id": bulletin_id,
            "title": entry.title,
            "type": bulletin_type,
            "date": entry.published,
            "link": entry.link
        })
    return bulletins

# Extraction des CVE d’un bulletin ANSSI (en JSON)
def extract_cves_from_bulletin(bulletin_id):
    url = f"https://www.cert.ssi.gouv.fr/avis/{bulletin_id}/json/"
    try:    # try pour éviter crash du code si serveur ne répond pas
        response = requests.get(url)
        if response.status_code != 200: # code 200 = tout est ok
            return []
        data = response.json()
        cves = list({cve.get("name") for cve in data.get("cves", []) if cve.get("name")})
        # Sécurité : si le champ cves est vide, trouver dans le json les regex correspondant au format
        if not cves:
            cves = list(set(re.findall(r"CVE-\d{4}-\d{4,7}", str(data))))
        return cves
    except Exception:
        return []

# Enrichissement des CVE via API MITRE 
def enrich_cve_mitre(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:    # try pour éviter crash du code si serveur ne répond pas
        response = requests.get(url)
        data = response.json()
        # récupère le dictionnaire cna contenus dans le dico containers, qui contient tous les sous-dicos intéressants
        # si l'un des deux n'existe pas (mauvais formatage) crée un dico vide pour éviter crash
        container = data.get("containers", {}).get("cna", {})

        # Description
        # récupère les descriptions anglaises si elles existent, sinon écrit "Non disponible"
        description = next((d.get("value") for d in container.get("descriptions", []) if d.get("lang") == "en"), "Non disponible")

        # Score CVSS + Gravité
        metrics = container.get("metrics", [])
        cvss_score = None
        severity = "Non disponible"
        for m in metrics:
            # teste les deux différentes versions 
            for version in ["cvssV3_1", "cvssV3_0"]:
                if version in m:
                    cvss_score = m[version].get("baseScore", "Non disponible")
                    severity = m[version].get("baseSeverity", "Non disponible")
                    break
            if cvss_score is not None:
                break

        # CWE
        problemtype = container.get("problemTypes", [])
        cwe_id = "Non disponible"
        cwe_desc = "Non disponible"
        if problemtype and "descriptions" in problemtype[0]:
            descs = problemtype[0]["descriptions"]
            if descs:
                cwe_id = descs[0].get("cweId", "Non disponible")
                cwe_desc = descs[0].get("description", "Non disponible")

        # Produits affectés
        affected = container.get("affected", [])
        vendors_products = []
        for product in affected:
            vendor = product.get("vendor", "Inconnu")
            product_name = product.get("product", "Inconnu")
            versions = [v["version"] for v in product.get("versions", []) if v.get("status") == "affected"]
            vendors_products.append((vendor, product_name, versions))

        return {
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "cwe_id": cwe_id,
            "cwe_desc": cwe_desc,
            "vendors_products": vendors_products
        }
    except Exception:
        return {}

# Score EPSS via API FIRST 
def get_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url)
        data = response.json()
        epss_data = data.get("data", [])
        if epss_data:
            return epss_data[0].get("epss", None)
    except Exception:
        return None
    return None

def send_email(to_email, subject, body):
    from_email = "testtest1xxxx@gmail.com"
    password = "uixi hjjn paje wtjd"
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()

# Pipeline principal en mode temps réel
def update_bulletin_data(csv_path="anssi_cve_data_reduced.csv", destinataire="votre@email.com"):
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        processed_ids = set(df["ID du bulletin"].unique())
    else:
        df = pd.DataFrame()
        processed_ids = set()

    bulletins = fetch_anssi_bulletins()
    new_data = []
    cve_cache = {}

    for bulletin in tqdm(bulletins, desc="Vérification des nouveaux bulletins"):
        if bulletin["bulletin_id"] in processed_ids:
            continue  # déjà traité

        cve_ids = extract_cves_from_bulletin(bulletin["bulletin_id"])
        time.sleep(1)
        lignes_mail = []

        for cve_id in cve_ids[:20]: # plafond à 20 CVE par bulletins par souci d'optimisation et de temps d'exec
            if cve_id in cve_cache:
                mitre_data, epss_score = cve_cache[cve_id]
            else:
                mitre_data = enrich_cve_mitre(cve_id)
                time.sleep(1)
                epss_score = get_epss_score(cve_id)
                time.sleep(1)
                cve_cache[cve_id] = (mitre_data, epss_score)

            if mitre_data and "vendors_products" in mitre_data:
                for vendor, product, versions in mitre_data["vendors_products"]:
                    ligne = {
                        "ID du bulletin": bulletin["bulletin_id"],
                        "Titre du bulletin": bulletin["title"],
                        "Type de bulletin": bulletin["type"],
                        "Date de publication": bulletin["date"],
                        "Lien du bulletin (ANSSI)": bulletin["link"],
                        "Identifiant CVE": cve_id,
                        "Score CVSS": mitre_data.get("cvss_score"),
                        "Base Severity": mitre_data.get("severity"),
                        "Type CWE": mitre_data.get("cwe_id"),
                        "Score EPSS": epss_score,
                        "Description": mitre_data.get("description"),
                        "Éditeur/Vendor": vendor,
                        "Produit": product,
                        "Versions affectées": ", ".join(versions) if versions else "Non spécifié"
                    }
                    new_data.append(ligne)
                    lignes_mail.append(f"- {cve_id} | {vendor} {product} | CVSS: {ligne['Score CVSS']} | EPSS: {ligne['Score EPSS']}")

        # Envoi du mail pour le bulletin
        if lignes_mail:
            body = f"🛡️ Nouveau bulletin ANSSI détecté : {bulletin['title']}\n\nLien : {bulletin['link']}\n\nCVE associées :\n" + "\n".join(lignes_mail)
            send_email(destinataire, f"Nouveau bulletin ANSSI : {bulletin['bulletin_id']}", body)

    # Mise à jour du DataFrame global
    if new_data:
        df = pd.concat([df, pd.DataFrame(new_data)], ignore_index=True)
        df = df.drop_duplicates()
        df.to_csv(csv_path, index=False)
        print("Mise à jour effectuée. Données exportées.")
        verifier_doublons_csv(csv_path)
    else:
        print("Aucun nouveau bulletin détecté.")

# MAIN
if __name__ == "__main__":
    INTERVAL_MINUTES = 60  # Scan lancé toutes les heures
    while True:
        print(f"\n Lancement du scan ANSSI à {time.strftime('%Y-%m-%d %H:%M:%S')}...\n")
        try:
            update_bulletin_data()
        except Exception as e:
            print(f"\n Erreur pendant l'exécution : {e}")
        print(f"\n Prochaine vérification dans {INTERVAL_MINUTES} minutes...\n")
        time.sleep(INTERVAL_MINUTES * 60)



