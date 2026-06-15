from time import sleep
import requests

from extraction_des_CVE import get_all_cve

RateLimiting = 0.2


def get_epss_score(cve_id):
    """API EPSS de FIRST : Permet d'obtenir la probabilité d'exploitation de la vulnérabilité."""
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    response = requests.get(url)
    data = response.json()
    # Extraire le score EPSS
    epss_data = data.get("data", [])
    if epss_data:
        return float(epss_data[0]["epss"])

    return None


'''
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
                    break'''


def mitre(cve_id):
    """API CVE de MITRE : Permet d'obtenir le score CVSS et le type CWE associé."""
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    sleep(RateLimiting/2)
    response = requests.get(url)
    # print(url)
    # print(response)
    data = response.json()

    print(f"--- MITRE ;; {cve_id}")

    #print(data)

    containers = data.get("containers", {})
    if not containers:
        print("!!!! cve with no containers !!!!")
        print(data)

        print()
        return cve_id, None, None, None, "Non disponible", get_epss_score(cve_id), "Non disponible", "Non disponible", "Non disponible"

    # Extraire la description
    descriptions = containers["cna"].get("descriptions", {})
    if descriptions:
        description = descriptions[0]["value"]
    else:
        description = "Non disponible"
        print("!!!! cve with no decriptions !!!!")
        for k, v in containers.items():
            print("key:", k, "; val:", v)
        print()
        rej = descriptions.get("rejectedReasons", {})
        rep = descriptions.get("replacedBy", {})
        if rej and rep:
            print("""!! with rej and rep""")
            return mitre(cve_id)

    # Extraire le score CVSS
    # ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
    # ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
    pre_cvss_score = containers["cna"].get("metrics", [])
    if pre_cvss_score and (pre_cvss_score[0].get("cvssV3_1", None) or pre_cvss_score[0].get("cvssV3_0", None) or pre_cvss_score[0].get("cvssV4_0", None)):
        pre_cvss_score = pre_cvss_score[0]
    else:
        if containers.get("adp", None):
            pre_cvss_score = containers["adp"][0].get("metrics", [])
            if not pre_cvss_score: #and len(containers["adp"])>1
                for i in range(1, len(containers["adp"])):
                    pre_cvss_score = containers["adp"][i].get("metrics", [])
                    if pre_cvss_score:
                        break
            if pre_cvss_score:
                pre_cvss_score = pre_cvss_score[0]

    base_severity = None
    if pre_cvss_score:
        cvss_score = pre_cvss_score.get("cvssV3_1", None)
        if cvss_score is None:
            cvss_score = pre_cvss_score.get("cvssV3_0", None)
        if cvss_score is None:
            cvss_score = pre_cvss_score.get("cvssV4_0", None)
        if cvss_score is None:
            pre_cvss_score = containers["cna"].get("metrics", [])
            if pre_cvss_score and len(pre_cvss_score) > 1:
                for i in range(1, len(pre_cvss_score)):
                    if (pre_cvss_score[i].get("cvssV3_1", None) or pre_cvss_score[i].get("cvssV3_0", None) or pre_cvss_score[i].get("cvssV4_0", None)):
                        pre_cvss_score = pre_cvss_score[i]
            if pre_cvss_score and not (type(pre_cvss_score) is list):
                cvss_score = pre_cvss_score.get("cvssV3_1", None)
                if cvss_score is None:
                    cvss_score = pre_cvss_score.get("cvssV3_0", None)
                if cvss_score is None:
                    cvss_score = pre_cvss_score.get("cvssV4_0", None)
            else:
                cvss_score = None
        if cvss_score is not None:
            base_severity = cvss_score["baseSeverity"]
            cvss_score = cvss_score["baseScore"]
        else:
            print("!!!! cve with no cvss ?? !!!!")
            for k, v in containers.items():
                print("key:", k, "; val:", v)
            print()
            '''for k, v in pre_cvss_score.items():
                print("key:", k, "; val:", v)
            print()'''
    else:
        cvss_score = None

    # CWE
    cwe = cwe_desc = None
    problem_type = containers["cna"].get("problemTypes", [])
    if not problem_type or (not problem_type[0]["descriptions"][0].get("cweId", None)):
        if containers.get("adp", None):
            problem_type = containers["adp"][0].get("problemTypes", [])
    if problem_type:
        first_cwe = problem_type[0]  ##pour l'instant on fait que le 1er
        cwe = first_cwe["descriptions"][0].get("cweId", None)
        cwe_desc = first_cwe["descriptions"][0].get("description", "Non disponible")
    if not problem_type or cwe is None:
        print("!!!! cve with no cwe ?? !!!!")
        print(cwe_desc)
        for k, v in containers.items():
            print("key:", k, "; val:", v)
        print()


    #
    """
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
    """

    # Extraire les produits affectés
    affected = containers["cna"].get("affected", [])
    vendor = "Non disponible"
    product_name = "Non disponible"
    if affected:
        vendor = affected[0].get("vendor", "Non disponible")
        product_name = affected[0].get("product", "Non disponible")


    # EPSS
    epss_score = get_epss_score(cve_id)

    return cve_id, cvss_score, base_severity, cwe, cwe_desc, epss_score, description, vendor, product_name


# %% zone du main
if __name__ == '__main__':
    cve_id = "CVE-2024-47177"
    mitre(cve_id)

    all_cve = get_all_cve()
    print(
        f"# It will take {(len(all_cve) * RateLimiting) / 60}min to do MITRE and FIRST on all CVEs.")
    for c in all_cve:
        mitre(c)

    ##
    enriched_data = []
    for cve in all_cve:
        epss = get_epss_score(cve)

        enriched_data.append({
            "cve_id": cve,
            "epss": epss
        })
    print(enriched_data)
