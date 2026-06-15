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


def get_rss_feed_avis():
    return get_rss_feed("https://www.cert.ssi.gouv.fr/avis/feed/")


def get_rss_feed_alertes():
    return get_rss_feed("https://www.cert.ssi.gouv.fr/alerte/feed/")


# %% zone du main
if __name__ == '__main__':

    url = "https://www.cert.ssi.gouv.fr/avis/feed/"
    rss_feed = get_rss_feed(url)
    #print(rss_feed)
    for entry in rss_feed.entries:
        print("Titre :", str(entry.title).split(" (")[0])
        print("Description:", entry.description)
        print("Lien :", entry.link)
        print("Date :", entry.published[5:-15])
        print(entry.link[34:-1]) #avis
        #print(entry.link[36:-1]) #alerte
        print()

    """for k, v in rss_feed.items():
        print("key:", k, "; val:", v)"""

