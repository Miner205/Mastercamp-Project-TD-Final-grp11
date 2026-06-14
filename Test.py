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

