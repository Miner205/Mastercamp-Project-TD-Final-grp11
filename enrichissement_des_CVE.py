import requests
import re
from time import sleep
import requests


def get_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    response = requests.get(url)
    data = response.json()

    epss_data = data.get("data", [])

    if len(epss_data) > 0:
        return float(epss_data[0]["epss"])

    return None

def enrich_cve(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    try:
        response = requests.get(url)
        data = response.json()

        #Extraire cve
        epss_score = get_epss_score(cve_id)

        #Extraire cna
        cna = data["containers"]["cna"]

        # Extraire la description
        description = data["containers"]["cna"]["descriptions"][0]["value"]
        # Extraire le score CVSS
        #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
        #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
        cvss_score = None

        for metric in cna.get("metrics", []):
            print(metric.keys())
            for key, value in metric.items():
                if key.lower().startswith("cvss"):
                    cvss_score = value.get("baseScore")
                    if cvss_score is not None:
                        break
            if cvss_score is not None:
                break

            # Cas format/other/content
            if metric.get("format") == "CVSS":

                other = metric.get("other", {})
                content = other.get("content", {})

                cvss_score = content.get("baseScore")

                if cvss_score is not None:
                    break



        cwe = "Non disponible"
        cwe_desc="Non disponible"

        problemtype = data["containers"]["cna"].get("problemTypes", [])

        if problemtype and "descriptions" in problemtype[0]:
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")
            # Extraire les produits affectés

        affected = data["containers"]["cna"].get("affected", [])

        vendor = "Non disponible"
        product_name = "Non disponible"

        vendor = affected[0].get("vendor", "Non disponible")
        product_name = affected[0].get("product", "Non disponible")

        return {
            "cve_id": cve_id,
            "cvss": cvss_score,
            "cwe": cwe,
            "cwe_desc": cwe_desc,
            "vendor": vendor,
            "product": product_name,
            "description": description,
            "epss": epss_score
        }
    except Exception as e:
        print(f"Erreur pour {cve_id}: {e}")
        return None
