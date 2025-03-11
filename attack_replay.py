#sudo apt-get install tcpreplay
# subject to change but an idea

import os
import time

def replay_pcap(pcap_file, interface):
    command = f"sudo tcpreplay --intf1={interface} {pcap_file}"
    os.system(command)
    print(f"[+] Replay finished: {pcap_file}")

if __name__ == "__main__":
    pcap_file = "attack.pcap"  # replace downloaded attack PCAP file from dataset, mostly IoT-23 dataset
    interface = "eth0"

    replay_pcap(pcap_file, interface)
