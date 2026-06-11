import pandas as pd
import os
import json
import requests
import feedparser
from time import sleep

RateLimiting = 2


def get_rss_feed(url):
    sleep(RateLimiting)
    rss_f = feedparser.parse(url)
    return rss_f


# %% zone du main
if __name__ == '__main__':

    url = "https://www.cert.ssi.gouv.fr/feed/"
    rss_feed = get_rss_feed(url)
    print(rss_feed)
    for entry in rss_feed.entries:
        print("Titre :", entry.title)
        print("Description:", entry.description)
        print("Lien :", entry.link)
        print("Date :", entry.published)

    """for k, v in rss_feed.items():
        print("key:", k, "; val:", v)"""

