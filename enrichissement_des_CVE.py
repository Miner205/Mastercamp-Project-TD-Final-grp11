import requests
import re
from time import sleep
import requests


def enrich_cve(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    try:
        response = requests.get(url)
        data = response.json()

        epss_score = data.get("data", [])

        #Extraire cna
        cna = data["containers"]["cna"]

        # Extraire la description
        description = data["containers"]["cna"]["descriptions"][0]["value"]
        # Extraire le score CVSS
        #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
        #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
        cvss_score = None

        for metric in cna.get("metrics", []):
            print(metric.key())
            for key, value in metric.items():
                if key.lower().startswith("cvss"):
                    cvss_score = value.get("baseScore")
                    if cvss_score is not None:
                        break
            if cvss_score is not None:
                break



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

        return {
            "cve_id": cve_id,
            "cvss": cvss_score,
            "cwe": cwe,
            "cwe_desc": cwe_desc,
            "vendor": vendor,
            "product": product,
            "description": description,
            "epss": epss_score
        }
    except Exception as e:
        print(f"Erreur pour {cve_id}: {e}")
        return None
