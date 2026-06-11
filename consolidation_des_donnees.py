import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import os
import json

# DataFrame Pandas


def get_df_temp(dir_path):
    folders = [os.path.join(dir_path, f) for f in os.listdir(dir_path)]
    files = []
    for folder in folders:
        files += [os.path.join(folder, f) for f in os.listdir(folder)]
    print(files[:10])
    data = []
    try:
        for file in files[:100]:
            with open(file, "r") as f:
                data.append(json.load(f))
    except Exception as e:
        print(e)
    print(data[0])

    df = pd.DataFrame(data)
    print(df.columns)


# %% zone du main
if __name__ == '__main__':
    df = get_df_temp("data/")
