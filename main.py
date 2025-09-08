#Étape 1 : Extraction des Flux RSS

import feedparser
url = "https://www.cert.ssi.gouv.fr/avis/feed"
rss_feed = feedparser.parse(url)
for entry in rss_feed.entries:
    print("Titre :", entry.title)
    print("Description:", entry.description)
    print("Lien :", entry.link)
    print("Date :", entry.published)

#Étape 2 : Extraction des CVE

import requests
import re
url = "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/json/"
response = requests.get(url)
data = response.json()
#Extraction des CVE reference dans la clé cves du dict data
ref_cves=list(data["cves"])
#attention il s’agit d’une liste des dictionnaires avec name et url comme clés
print( "CVE référencés ", ref_cves)
# Extraction des CVE avec une regex
cve_pattern = r"CVE-\d{4}-\d{4,7}"
cve_list = list(set(re.findall(cve_pattern, str(data))))
print("CVE trouvés :", cve_list)

#Étape 3 : Enrichissement des CVE : exemple de connexion à l'API CVE

import requests
cve_id = "CVE-2023-24488"
url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
response = requests.get(url)
data = response.json()
# Extraire la description
description = data["containers"]["cna"]["descriptions"][0]["value"]
# Extraire le score CVSS
#ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
#ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
cvss_score =data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
cwe = "Non disponible"
cwe_desc="Non disponible"
problemtype = data["containers"]["cna"].get("problemTypes", {})
if problemtype and "descriptions" in problemtype[0]:
    cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
    cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")
# Extraire les produits affectés
affected = data["containers"]["cna"]["affected"]
for product in affected:
    vendor = product["vendor"]
    product_name = product["product"]
    versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
    print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")
# Afficher les résultats
print(f"CVE : {cve_id}")
print(f"Description : {description}")
print(f"Score CVSS : {cvss_score}")
print(f"Type CWE : {cwe}")
print(f"CWE Description : {cwe_desc}")

# Étape 4 : Consolidation des Données