import pandas as pd
import os
from extraction_des_CVE import *
from enrichissement_des_CVE import *

CSV_FILE = "cve_dataset.csv"

if os.path.exists(CSV_FILE):
    df = pd.read_csv(CSV_FILE)
else:
    df = pd.DataFrame()

existing_cves = set()

if not df.empty:
    existing_cves = set(df["cve_id"])

new_data = []

rss_feed = get_rss_feed_avis()
url = rss_feed.entries[0].link

test = get_cve(url)
print(test)

all_cve = get_all_cve()
print(all_cve)


for cve in all_cve:

    if cve in existing_cves:
        continue

    print(f"Nouvelle CVE : {cve}")

    enriched_data = enrich_cve(cve)

    if enriched_data is not None:
        new_data.append(enriched_data)

if new_data:

    new_df = pd.DataFrame(new_data)

    df = pd.concat(
        [df, new_df],
        ignore_index=True
    )

    df.to_csv(
        CSV_FILE,
        index=False
    )