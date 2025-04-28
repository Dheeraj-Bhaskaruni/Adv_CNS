#!/usr/bin/env python3
import time, joblib, pandas as pd
from scapy.all import sniff, IP

# ── CONFIG ───────────────────────────────────────────────────────────
SNIFF_IFACE    = "veth1"
IDLE_TIMEOUT   = 3          # per-flow idle
GLOBAL_IDLE    = 5          # stop after 5 s of total silence
CHUNK          = 1          # sniff() timeout
MODEL_PATH     = "ids_rf_model.pkl"
PROTO_MAP      = {6: "tcp", 17: "udp", 1: "icmp"}

# ── LOAD MODEL ───────────────────────────────────────────────────────
rf_model, enc = joblib.load(MODEL_PATH)

# ── STATE ────────────────────────────────────────────────────────────
flows = {}
last_packet_ts = time.time()
total = benign = nonbenign = 0

def classify_flow(key, st):
    global total, benign, nonbenign
    feat = {
        "id.orig_p":  key[2],
        "id.resp_p":  key[3],
        "proto":      enc.transform([PROTO_MAP.get(key[4], str(key[4]))])[0],
        "duration":   (st["last_ts"] - st["first_ts"]) * 1000,
        "orig_bytes": st["bytes_src2dst"],
        "resp_bytes": st["bytes_dst2src"],
        "orig_pkts":  st["pkts_src2dst"],
        "resp_pkts":  st["pkts_dst2src"],
    }
    pred = rf_model.predict(pd.DataFrame([feat]))[0]
    total += 1
    if pred == 1:
        benign += 1
        label = "benign"
    else:
        nonbenign += 1
        label = "non-benign"
    print(f"[#{total}] {key} → {label} "
          f"(benign={benign}, non-benign={nonbenign})")

def expire_idle(now):
    idle = [k for k, st in flows.items() if now - st["last_ts"] > IDLE_TIMEOUT]
    for k in idle:
        classify_flow(k, flows.pop(k))

def on_pkt(pkt):
    global last_packet_ts
    if IP not in pkt:
        return
    now = pkt.time
    last_packet_ts = now           # mark activity
    expire_idle(now)               # close other idle flows

    ip = pkt[IP]
    l4 = ip.payload
    sport = getattr(l4, "sport", 0)
    dport = getattr(l4, "dport", 0)
    proto = ip.proto

    # canonical bidirectional key
    if (ip.src, sport) <= (ip.dst, dport):
        key = (ip.src, ip.dst, sport, dport, proto)
        rev = True
    else:
        key = (ip.dst, ip.src, dport, sport, proto)
        rev = False

    st = flows.setdefault(key, {
        "first_ts": now, "last_ts": now,
        "pkts_src2dst": 0, "pkts_dst2src": 0,
        "bytes_src2dst": 0, "bytes_dst2src": 0
    })
    st["last_ts"] = now
    length = len(pkt)
    if rev:                          # pkt.src == key[0]
        st["pkts_src2dst"]  += 1
        st["bytes_src2dst"] += length
    else:
        st["pkts_dst2src"]  += 1
        st["bytes_dst2src"] += length

# ── MAIN LOOP ────────────────────────────────────────────────────────
print(f"[*] Sniffing on {SNIFF_IFACE} …")
try:
    while True:
        sniff(iface=SNIFF_IFACE, filter="ip",
              prn=on_pkt, store=False, timeout=CHUNK)

        now = time.time()
        expire_idle(now)                         # flush idle every chunk

        # Stop if no packets for GLOBAL_IDLE and nothing active
        if (now - last_packet_ts > GLOBAL_IDLE) and not flows:
            break
except KeyboardInterrupt:
    pass

# ── FINAL FLUSH ──────────────────────────────────────────────────────
expire_idle(time.time())
for k, st in list(flows.items()):               # still-live flows
    classify_flow(k, st)

print(f"[*] Finished – total flows {total} (benign={benign}, "
      f"non-benign={nonbenign})")

