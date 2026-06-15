import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.cluster import KMeans
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt


def prepare_data(csv):
    df = pd.read_csv(csv)
    new_df = df.dropna(subset=["CVSS"])
    new_df = new_df.dropna(subset=["EPSS"])
    new_df.reset_index(drop=True, inplace=True)
    new_df["EPSS"] = new_df["EPSS"]*10
    return new_df


def get_training_data():
    return pd.read_csv("train_data.csv")


def do_knn_classification(display):
    model = KNeighborsClassifier(n_neighbors=3)
    # handpicked data (not very representative)
    training_data = get_training_data()
    x_training_data = training_data.drop(columns=["CLASS"])
    y_training_data = training_data["CLASS"]
    model.fit(x_training_data, y_training_data)

    test_data = prepare_data("our_dataset.csv")
    # 2: always sends email, 1: sends email to subscriber with warning level 0 and 1, 0: sends email only to subscriber with warning level 0
    y_pred = model.predict(test_data[["CVSS", "EPSS"]])

    if display is True:
        plt.scatter(x_training_data["CVSS"], x_training_data["EPSS"], c=y_training_data, cmap="brg")
        plt.show()
        plt.scatter(test_data["CVSS"], test_data["EPSS"], c=y_pred, cmap="brg")
        plt.show()

    return test_data, y_pred


# since KMeans is unsupervised I did not choose the values of the labels
def do_kmeans(display):
    model = KMeans(3, random_state=42)
    training_data = get_training_data()
    x_training_data = training_data.drop(columns=["CLASS"])
    y_training_data = training_data["CLASS"]
    model.fit(x_training_data)

    test_data = prepare_data("our_dataset.csv")
    # label 0 is priority 2, label 1 is priority 1, label 2 is priority 0
    y_pred = model.predict(test_data[["CVSS", "EPSS"]])

    if display is True:
        plt.scatter(x_training_data["CVSS"], x_training_data["EPSS"], c=y_training_data, cmap="brg")
        plt.show()
        plt.scatter(test_data["CVSS"], test_data["EPSS"], c=y_pred, cmap="brg")
        plt.show()

    return test_data, y_pred


if __name__ == '__main__':
    #knn_prediction = do_knn_classification(True)
    kmeans_prediction = do_kmeans(True)
