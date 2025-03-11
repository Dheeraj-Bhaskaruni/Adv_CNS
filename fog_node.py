# pip3 install numpy pandas scikit-learn paho-mqtt joblib
# Fog Node ML-Based Detection & Alerting
# This is quite confusing where to start, in progress

import joblib
import numpy as np
import pandas as pd
import time
import paho.mqtt.client as mqtt

model = joblib.load("rf_model.pkl")  # Your trained Random Forest ML model

MQTT_BROKER = "192.168.1.100"  # Gateway IP
MQTT_TOPIC = "fog/alerts"

mqtt_client = mqtt.Client()
mqtt_client.connect(MQTT_BROKER, 1883, 60)


def extract_features():
    features = np.random.rand(1, 10)
    return features


def send_alert(alert_message):
    mqtt_client.publish(MQTT_TOPIC, alert_message)
    print("[ALERT SENT]:", alert_message)


def detect_traffic():
    print("[+] Starting fog node ML-based detection...")
    while True:
        features = extract_features()
        prediction = model.predict(features)

        if prediction[0] == 1:
            alert_message = f"Malicious activity detected! Features: {features.tolist()}"
            send_alert(alert_message)
        else:
            print("[INFO]: Traffic normal.")

        time.sleep(2)


if __name__ == "__main__":
    detect_traffic()
