import pandas as pd
from enrichissement_des_CVE import *
from pprint import pprint

df = pd.read_csv("our_dataset.csv")

missing = df[df["CVSS"].isna()]

for cve in missing["CVE"].header(10):

    print("\n", cve)

    url = f"https://cveawg.mitre.org/api/cve/{cve}"
    data = requests.get(url).json()

    metrics = data["containers"]["cna"].get("metrics", [])

    pprint(metrics)

    print("=" * 80)
