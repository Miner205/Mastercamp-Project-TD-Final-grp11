import requests
import re
from time import sleep

from extraction_des_flux_RSS import get_rss_feed_avis, get_rss_feed_alertes

RateLimiting = 2


def get_cve(url):
    sleep(RateLimiting)
    response = requests.get(url + "json/")
    #print(url)
    #print(response)
    data = response.json()
    #print(data)
    # Extraction des CVE reference dans la clé cves du dict data
    ref_cves = list(data["cves"])
    #print("CVE référencés :", ref_cves)

    """# Extraction des CVE avec une regex
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_list = list(set(re.findall(cve_pattern, str(data))))
    print("CVE trouvés :", cve_list)
    """
    cve_list = [elt['name'] for elt in ref_cves]
    #print(cve_list)
    return cve_list


def get_all_cve():
    print("\n--------------------------")
    rss_feed_avis = get_rss_feed_avis()
    rss_feed_alertes = get_rss_feed_alertes()
    print(f"# It will take {(len(rss_feed_avis.entries)+len(rss_feed_avis.entries)) * RateLimiting}s to retrieve all CVEs from all entries.")
    all_c = []
    i_entry = 0
    for entry in rss_feed_avis.entries:
        url = entry.link
        c = get_cve(url)
        all_c += c
        i_entry += 1
        print(f"CVEs from entry n°{i_entry} retrieved.")
    for entry in rss_feed_alertes.entries:
        url = entry.link
        c = get_cve(url)
        all_c += c
        i_entry += 1
        print(f"CVEs from entry n°{i_entry} retrieved.")
    print("# All CVEs retrieved.")
    print("--------------------------\n")
    return all_c


# %% zone du main
if __name__ == '__main__':

    rss_feed = get_rss_feed_avis()
    url = rss_feed.entries[0].link

    test = get_cve(url)
    print(test)

    all_cve = get_all_cve()
    print(all_cve)
