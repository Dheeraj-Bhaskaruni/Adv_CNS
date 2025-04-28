#!/usr/bin/env python3
import pyshark, pandas as pd, joblib, signal, sys, time

INTERFACE  = "enp3s0"          # RX side
MODEL_FILE = "ids_rf_model.pkl"
IDLE_SEC   = 10              # idle timeout (non-TCP)
BENIGN_ID = 1

# ─── load model and init proto map ──────────────────────────
rf_model, enc = joblib.load(MODEL_FILE)
proto2int = {p: i for i, p in enumerate(enc.classes_)}
next_code = len(proto2int)
def proto_code(p):
    global next_code
    if p not in proto2int:
        proto2int[p] = next_code
        next_code += 1
    return proto2int[p]

# ─── flow store ─────────────────────────────────────────────
flows = {}                    # key → flow dict
flow_no = benign = nonbenign = 0

def classify(flow):
    global flow_no, benign, nonbenign
    dur = (flow['last_ts'] - flow['start_ts'])*1000
    row = pd.DataFrame([{
        "id.orig_p":  flow['sport'],
        "id.resp_p":  flow['dport'],
        "proto":      proto_code(flow['proto']),
        "duration":   dur,
        "orig_bytes": flow['orig_bytes'],
        "resp_bytes": flow['resp_bytes'],
        "orig_pkts":  flow['orig_pkts'],
        "resp_pkts":  flow['resp_pkts'],
    }])
    pred       = rf_model.predict(row)[0]
    is_benign  = (pred == BENIGN_ID)
    label      = "Benign" if is_benign else "Non-Benign"
    flow_no   += 1
    benign    += is_benign
    nonbenign += (not is_benign)
    print(f"Flow {flow_no:>5} → {label:10} "
          f"{flow['src']}:{flow['sport']} → {flow['dst']}:{flow['dport']} "
          f"{flow['proto'].upper():4} dur={dur:.0f} ms  "
          f"Totals B:{benign} NB:{nonbenign}")

def tcp_done(f):
    return (f['fin_orig'] and f['fin_resp']) or f['rst_orig'] or f['rst_resp']

def expire_idle(now):
    for k, f in list(flows.items()):
        if f['proto'] != 'tcp' and now - f['last_ts'] >= IDLE_SEC:
            classify(f); flows.pop(k, None)

def flush_all(*_):
    for f in list(flows.values()):
        classify(f)
    print("\nCapture finished.")
    sys.exit(0)

signal.signal(signal.SIGINT, flush_all)

print(f"Listening on {INTERFACE}  (Ctrl-C to stop)")
cap = pyshark.LiveCapture(interface=INTERFACE)   # no keep_packets here

for pkt in cap.sniff_continuously():
    if not hasattr(pkt, 'ip'):
        continue
    ts   = float(pkt.sniff_timestamp)
    src  = pkt.ip.src
    dst  = pkt.ip.dst
    ip_proto = int(pkt.ip.proto)

    if ip_proto == 6 and hasattr(pkt, "tcp"):
        proto = "tcp"
        sport, dport = int(pkt.tcp.srcport), int(pkt.tcp.dstport)
    elif ip_proto == 17 and hasattr(pkt, "udp"):
        proto = "udp"
        sport, dport = int(pkt.udp.srcport), int(pkt.udp.dstport)
    else:
        proto = pkt.highest_layer.lower()
        sport = dport = 0

    key  = (src, sport, dst, dport, proto)
    rev  = (dst, dport, src, sport, proto)
    if key in flows:
        f = flows[key]; direction = 'orig'
    elif rev in flows:
        f = flows[rev]; direction = 'resp'
    else:
        f = flows[key] = {
            "src":src, "sport":sport, "dst":dst, "dport":dport,
            "proto":proto, "start_ts":ts, "last_ts":ts,
            "orig_bytes":0, "resp_bytes":0,
            "orig_pkts":0,  "resp_pkts":0,
            "fin_orig":False,"fin_resp":False,
            "rst_orig":False,"rst_resp":False}
        direction = 'orig'

    f["last_ts"] = ts
    length = int(pkt.length) if hasattr(pkt, "length") else 0
    if direction == 'orig':
        f['orig_pkts']  += 1; f['orig_bytes'] += length
    else:
        f['resp_pkts']  += 1; f['resp_bytes'] += length

    if proto == "tcp" and hasattr(pkt, "tcp"):
        if int(pkt.tcp.flags_fin):
            f['fin_orig' if direction=='orig' else 'fin_resp'] = True
        if int(pkt.tcp.flags_reset):
            f['rst_orig' if direction=='orig' else 'rst_resp'] = True
        if tcp_done(f):
            classify(f)
            flows.pop(key, None); flows.pop(rev, None)
            continue

    expire_idle(ts)

