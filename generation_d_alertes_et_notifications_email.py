import pandas as pd
from model_machine_learning import do_knn_classification, do_kmeans
import smtplib
from email.mime.text import MIMEText


from_email = "votre_email@test.com"
password = "mot_de_passe_test"


def select_subscriber(subscriber_csv, data, label):
    subscribers = pd.read_csv(subscriber_csv)
    for report_name, report in data.groupby("ID_ANSSI"):
        email_level = 0
        last_index = 0
        for index, row in report.iterrows():
            last_index = index
            if label[index] == 1:
                email_level = 2
            elif email_level != 2 and label[index] == 0:
                email_level = 1
        for index, subscriber in subscribers.iterrows():
            if subscriber["organization"] == report["Éditeur"][last_index] and subscriber["warning level"] <= email_level:
                send_email(subscriber["email"], report["Éditeur"][last_index] + " " + report["Type"][last_index] + " CVE niveau " + str(email_level), report["Titre_ANSSI"][last_index] + "\n" + report["Lien_ANSSI"][last_index])
                print(subscriber["name"] + " " + report["Éditeur"][last_index] + " " + report["Type"][last_index] + " CVE niveau " + str(email_level))


def send_email(to_email, subject, body):
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    """server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()"""


if __name__ == '__main__':
    #prepared_data, predicted_label = do_knn_classification(False)
    prepared_data, predicted_label = do_kmeans(False)
    select_subscriber("subscibers.csv", prepared_data, predicted_label)
