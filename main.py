import pandas as pd
import os
from extraction_des_flux_RSS import *
from extraction_des_CVE import *
from enrichissement_des_CVE import *


# Pour créer le csv :


CSV_FILE = "our_dataset.csv"

'''if os.path.exists(CSV_FILE):
    df = pd.read_csv(CSV_FILE)
else:
    df = pd.DataFrame()

existing_cves = set()

if not df.empty:
    existing_cves = set(df["CVE"])'''

new_data = []

rss_feed_avis = get_rss_feed_avis()
rss_feed_alertes = get_rss_feed_alertes()

print(
    f"# It will take {(len(rss_feed_avis.entries) + len(rss_feed_avis.entries)) * RateLimiting}s to retrieve all CVEs from all entries.")
#print(
 #       f"# It will take {(len(all_cve) * RateLimiting) / 60}min to do MITRE and FIRST on all CVEs.")


# Avis
for entry in rss_feed_avis.entries:

    '''if cve in existing_cves:
        continue'''

    url = entry.link
    cves = get_cve(url)

    for cve in cves:

        new_row = {
            "ID_ANSSI": entry.link[34:-1],
            "Titre_ANSSI": str(entry.title).split(" (")[0],
            "Type": "Avis",  # Avis ou Alerte
            "Date": entry.published[5:-15],
            "Lien_ANSSI": entry.link
        }

        new_row["CVE"], new_row["CVSS"], new_row["Base_Severity"], new_row["CWE"], new_row["CWE_description"], new_row["EPSS"], new_row["CVE_description"], new_row["Éditeur"], new_row["Produit"] = mitre(cve)

        new_data.append(new_row)

# Alertes
for entry in rss_feed_alertes.entries:

        '''if cve in existing_cves:
            continue'''

        url = entry.link
        cves = get_cve(url)

        for cve in cves:
            new_row = {
                "ID_ANSSI": entry.link[36:-1],
                "Titre_ANSSI": str(entry.title).split(" (")[0],
                "Type": "Alerte",  # Avis ou Alerte
                "Date": entry.published[5:-15],
                "Lien_ANSSI": entry.link
            }

            new_row["CVE"], new_row["CVSS"], new_row["Base_Severity"], new_row["CWE"], new_row["CWE_description"], new_row[
                "EPSS"], new_row["CVE_description"], new_row["Éditeur"], new_row["Produit"] = mitre(cve)

            new_data.append(new_row)


if new_data:

    '''new_df = pd.DataFrame(new_data)

    df = pd.concat(
        [df, new_df],
        ignore_index=True
    )'''
    df = pd.DataFrame(new_data)

    df.to_csv(CSV_FILE, index=False)
