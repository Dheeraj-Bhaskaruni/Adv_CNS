# pip3 install paho-mqtt flask
# idea based on rfid readers, multiple message check

import paho.mqtt.client as mqtt
import datetime

MQTT_BROKER = "0.0.0.0"
MQTT_TOPIC = "fog/alerts"

def on_connect(client, userdata, flags, rc):
    print("[+] Gateway connected with code:", rc)
    client.subscribe(MQTT_TOPIC)

def on_message(client, userdata, msg):
    alert = msg.payload.decode()
    print(f"[ALERT RECEIVED at {datetime.datetime.now()}]: {alert}")
    with open("alerts.log", "a") as log_file:
        log_file.write(f"{datetime.datetime.now()}: {alert}\n")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect(MQTT_BROKER, 1883, 60)
client.loop_forever()
