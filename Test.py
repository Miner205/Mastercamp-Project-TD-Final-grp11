import pandas as pd
import requests
from pprint import pprint
from enrichissement_des_CVE import *

df=pd.read_csv("cve_dataset.csv")



import pandas as pd
import requests
from pprint import pprint

df = pd.read_csv("cve_dataset.csv")

missing = df[df["cvss"].isna()]

for cve in missing["cve_id"].header(10):

    print("\n", cve)

    url = f"https://cveawg.mitre.org/api/cve/{cve}"
    data = requests.get(url).json()

    metrics = data["containers"]["cna"].get("metrics", [])

    pprint(metrics)

    print("=" * 80)