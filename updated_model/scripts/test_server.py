import requests
import random
import time
import statistics

SERVER_URL = "http://localhost:5000/predict"

TOTAL_REQUESTS = 10
CONCURRENCY = 1

# Base benign flow template
flow_ddos = {
"Init Fwd Win Byts":8192,"Fwd Seg Size Min":20,"Flow IAT Mean":1,"Fwd Header Len":40,
"Flow IAT Max":3,"Flow Duration":5,"Fwd IAT Tot":3,"Fwd Pkts/s":200000,
"Flow Pkts/s":250000,"Fwd IAT Max":2,"Bwd Pkts/s":0,"Flow IAT Min":1,
"Fwd IAT Mean":1,"Fwd IAT Min":1,"Bwd Header Len":0,"Init Bwd Win Byts":0,
"Subflow Fwd Byts":2000000,"Fwd Pkt Len Max":60,"Pkt Len Max":60,
"Fwd Seg Size Avg":60,"Pkt Size Avg":60,"TotLen Fwd Pkts":2000000,
"Bwd Pkt Len Mean":0,"Fwd Pkt Len Mean":60,"TotLen Bwd Pkts":0,
"Tot Fwd Pkts":30000,"Pkt Len Mean":60,"Bwd Seg Size Avg":0,"Pkt Len Var":0,
"Subflow Bwd Byts":0,"Bwd Pkt Len Max":0,"Subflow Fwd Pkts":30000,
"Pkt Len Std":0,"Subflow Bwd Pkts":0,"Tot Bwd Pkts":0,"Flow IAT Std":0,
"Fwd Pkt Len Std":0,"Bwd Pkt Len Std":0,"Flow Byts/s":500000000,
"Bwd IAT Tot":0,"Bwd IAT Max":0,"Fwd IAT Std":0,"Bwd IAT Mean":0,
"Fwd Act Data Pkts":30000,"Bwd IAT Std":0,"Bwd IAT Min":0,
"ECE Flag Cnt":0,"RST Flag Cnt":0,"Fwd Pkt Len Min":60,"ACK Flag Cnt":0,
"Bwd Pkt Len Min":0,"Idle Max":0,"Down/Up Ratio":0,"Idle Mean":0,
"Idle Min":0,"Pkt Len Min":60,"PSH Flag Cnt":0,"URG Flag Cnt":0,
"Active Max":1,"Active Min":1,"Active Mean":1,"Idle Std":0,
"Active Std":0,"Fwd PSH Flags":0,"SYN Flag Cnt":1,"FIN Flag Cnt":0,
"Fwd Byts/b Avg":0,"Fwd URG Flags":0
}


flow_slow_scan = {
"Init Fwd Win Byts":8192,"Fwd Seg Size Min":20,"Flow IAT Mean":10000000,
"Fwd Header Len":40,"Flow IAT Max":20000000,"Flow Duration":3600000000,
"Fwd IAT Tot":3000000000,"Fwd Pkts/s":0.001,"Flow Pkts/s":0.002,
"Fwd IAT Max":10000000,"Bwd Pkts/s":0,"Flow IAT Min":5000000,
"Fwd IAT Mean":10000000,"Fwd IAT Min":5000000,"Bwd Header Len":0,
"Init Bwd Win Byts":0,"Subflow Fwd Byts":300,"Fwd Pkt Len Max":60,
"Pkt Len Max":60,"Fwd Seg Size Avg":60,"Pkt Size Avg":60,
"TotLen Fwd Pkts":300,"Bwd Pkt Len Mean":0,"Fwd Pkt Len Mean":60,
"TotLen Bwd Pkts":0,"Tot Fwd Pkts":5,"Pkt Len Mean":60,
"Bwd Seg Size Avg":0,"Pkt Len Var":0,"Subflow Bwd Byts":0,
"Bwd Pkt Len Max":0,"Subflow Fwd Pkts":5,"Pkt Len Std":0,
"Subflow Bwd Pkts":0,"Tot Bwd Pkts":0,"Flow IAT Std":1000000,
"Fwd Pkt Len Std":0,"Bwd Pkt Len Std":0,"Flow Byts/s":0.1,
"Bwd IAT Tot":0,"Bwd IAT Max":0,"Fwd IAT Std":500000,
"Bwd IAT Mean":0,"Fwd Act Data Pkts":5,"Bwd IAT Std":0,
"Bwd IAT Min":0,"ECE Flag Cnt":0,"RST Flag Cnt":0,
"Fwd Pkt Len Min":60,"ACK Flag Cnt":0,"Bwd Pkt Len Min":0,
"Idle Max":10000000,"Down/Up Ratio":0,"Idle Mean":5000000,
"Idle Min":1000000,"Pkt Len Min":60,"PSH Flag Cnt":0,
"URG Flag Cnt":0,"Active Max":1,"Active Min":1,"Active Mean":1,
"Idle Std":1000000,"Active Std":0,"Fwd PSH Flags":0,
"SYN Flag Cnt":1,"FIN Flag Cnt":0,"Fwd Byts/b Avg":0,
"Fwd URG Flags":0
}

flow_exfiltration = {
"Init Fwd Win Byts": 8192,
"Fwd Seg Size Min": 20,
"Flow IAT Mean": 5000000,
"Fwd Header Len": 40,
"Flow IAT Max": 10000000,
"Flow Duration": 120000000,
"Fwd IAT Tot": 100000000,
"Fwd Pkts/s": 10,
"Flow Pkts/s": 12,
"Fwd IAT Max": 9000000,
"Bwd Pkts/s": 1,
"Flow IAT Min": 2000000,
"Fwd IAT Mean": 5000000,
"Fwd IAT Min": 1000000,
"Bwd Header Len": 20,
"Init Bwd Win Byts": 0,
"Subflow Fwd Byts": 20000000,
"Fwd Pkt Len Max": 1500,
"Pkt Len Max": 1500,
"Fwd Seg Size Avg": 1200,
"Pkt Size Avg": 1100,
"TotLen Fwd Pkts": 20000000,
"Bwd Pkt Len Mean": 100,
"Fwd Pkt Len Mean": 1200,
"TotLen Bwd Pkts": 2000,
"Tot Fwd Pkts": 15000,
"Pkt Len Mean": 1000,
"Bwd Seg Size Avg": 100,
"Pkt Len Var": 1000,
"Subflow Bwd Byts": 2000,
"Bwd Pkt Len Max": 200,
"Subflow Fwd Pkts": 15000,
"Pkt Len Std": 30,
"Subflow Bwd Pkts": 20,
"Tot Bwd Pkts": 20,
"Flow IAT Std": 500000,
"Fwd Pkt Len Std": 50,
"Bwd Pkt Len Std": 10,
"Flow Byts/s": 200000000,
"Bwd IAT Tot": 100000,
"Bwd IAT Max": 10000,
"Fwd IAT Std": 200000,
"Bwd IAT Mean": 10000,
"Fwd Act Data Pkts": 15000,
"Bwd IAT Std": 1000,
"Bwd IAT Min": 100,
"ECE Flag Cnt": 0,
"RST Flag Cnt": 0,
"Fwd Pkt Len Min": 1000,
"ACK Flag Cnt": 1,
"Bwd Pkt Len Min": 60,
"Idle Max": 1000000,
"Down/Up Ratio": 0,
"Idle Mean": 500000,
"Idle Min": 100000,
"Pkt Len Min": 60,
"PSH Flag Cnt": 0,
"URG Flag Cnt": 0,
"Active Max": 50000,
"Active Min": 20000,
"Active Mean": 30000,
"Idle Std": 200000,
"Active Std": 5000,
"Fwd PSH Flags": 0,
"SYN Flag Cnt": 1,
"FIN Flag Cnt": 0,
"Fwd Byts/b Avg": 0,
"Fwd URG Flags": 0
}

flow_c2_beacon = {
"Init Fwd Win Byts":8192,
"Fwd Seg Size Min":20,
"Flow IAT Mean":8000000,
"Fwd Header Len":40,
"Flow IAT Max":12000000,
"Flow Duration":240000000,
"Fwd IAT Tot":200000000,
"Fwd Pkts/s":2,
"Flow Pkts/s":3,
"Fwd IAT Max":10000000,
"Bwd Pkts/s":1,
"Flow IAT Min":4000000,
"Fwd IAT Mean":8000000,
"Fwd IAT Min":3000000,
"Bwd Header Len":20,
"Init Bwd Win Byts":0,
"Subflow Fwd Byts":12000,
"Fwd Pkt Len Max":300,
"Pkt Len Max":320,
"Fwd Seg Size Avg":250,
"Pkt Size Avg":260,
"TotLen Fwd Pkts":12000,
"Bwd Pkt Len Mean":200,
"Fwd Pkt Len Mean":240,
"TotLen Bwd Pkts":8000,
"Tot Fwd Pkts":50,
"Pkt Len Mean":240,
"Bwd Seg Size Avg":200,
"Pkt Len Var":100,
"Subflow Bwd Byts":8000,
"Bwd Pkt Len Max":300,
"Subflow Fwd Pkts":50,
"Pkt Len Std":10,
"Subflow Bwd Pkts":40,
"Tot Bwd Pkts":40,
"Flow IAT Std":1000000,
"Fwd Pkt Len Std":20,
"Bwd Pkt Len Std":15,
"Flow Byts/s":4000,
"Bwd IAT Tot":40000000,
"Bwd IAT Max":2000000,
"Fwd IAT Std":900000,
"Bwd IAT Mean":2000000,
"Fwd Act Data Pkts":50,
"Bwd IAT Std":100000,
"Bwd IAT Min":100000,
"ECE Flag Cnt":0,
"RST Flag Cnt":0,
"Fwd Pkt Len Min":200,
"ACK Flag Cnt":1,
"Bwd Pkt Len Min":200,
"Idle Max":10000000,
"Down/Up Ratio":0.8,
"Idle Mean":5000000,
"Idle Min":2000000,
"Pkt Len Min":200,
"PSH Flag Cnt":0,
"URG Flag Cnt":0,
"Active Max":200000,
"Active Min":100000,
"Active Mean":150000,
"Idle Std":1000000,
"Active Std":50000,
"Fwd PSH Flags":0,
"SYN Flag Cnt":1,
"FIN Flag Cnt":0,
"Fwd Byts/b Avg":0,
"Fwd URG Flags":0
}

flow_data_exfil = {
"Init Fwd Win Byts":8192,
"Fwd Seg Size Min":20,
"Flow IAT Mean":2000000,
"Fwd Header Len":40,
"Flow IAT Max":6000000,
"Flow Duration":300000000,
"Fwd IAT Tot":200000000,
"Fwd Pkts/s":20,
"Flow Pkts/s":22,
"Fwd IAT Max":5000000,
"Bwd Pkts/s":2,
"Flow IAT Min":500000,
"Fwd IAT Mean":2000000,
"Fwd IAT Min":200000,
"Bwd Header Len":20,
"Init Bwd Win Byts":0,
"Subflow Fwd Byts":20000000,
"Fwd Pkt Len Max":1500,
"Pkt Len Max":1500,
"Fwd Seg Size Avg":1200,
"Pkt Size Avg":1100,
"TotLen Fwd Pkts":20000000,
"Bwd Pkt Len Mean":100,
"Fwd Pkt Len Mean":1200,
"TotLen Bwd Pkts":2000,
"Tot Fwd Pkts":15000,
"Pkt Len Mean":1000,
"Bwd Seg Size Avg":100,
"Pkt Len Var":1000,
"Subflow Bwd Byts":2000,
"Bwd Pkt Len Max":200,
"Subflow Fwd Pkts":15000,
"Pkt Len Std":30,
"Subflow Bwd Pkts":20,
"Tot Bwd Pkts":20,
"Flow IAT Std":500000,
"Fwd Pkt Len Std":50,
"Bwd Pkt Len Std":10,
"Flow Byts/s":100000000,
"Bwd IAT Tot":100000,
"Bwd IAT Max":10000,
"Fwd IAT Std":200000,
"Bwd IAT Mean":10000,
"Fwd Act Data Pkts":15000,
"Bwd IAT Std":1000,
"Bwd IAT Min":100,
"ECE Flag Cnt":0,
"RST Flag Cnt":0,
"Fwd Pkt Len Min":1000,
"ACK Flag Cnt":1,
"Bwd Pkt Len Min":60,
"Idle Max":2000000,
"Down/Up Ratio":0.1,
"Idle Mean":1000000,
"Idle Min":200000,
"Pkt Len Min":60,
"PSH Flag Cnt":0,
"URG Flag Cnt":0,
"Active Max":50000,
"Active Min":20000,
"Active Mean":30000,
"Idle Std":200000,
"Active Std":5000,
"Fwd PSH Flags":0,
"SYN Flag Cnt":1,
"FIN Flag Cnt":0,
"Fwd Byts/b Avg":0,
"Fwd URG Flags":0
}

flow_reverse_shell = {
"Init Fwd Win Byts":8192,
"Fwd Seg Size Min":20,
"Flow IAT Mean":6000000,
"Fwd Header Len":40,
"Flow IAT Max":9000000,
"Flow Duration":180000000,
"Fwd IAT Tot":120000000,
"Fwd Pkts/s":1,
"Flow Pkts/s":2,
"Fwd IAT Max":8000000,
"Bwd Pkts/s":1,
"Flow IAT Min":2000000,
"Fwd IAT Mean":6000000,
"Fwd IAT Min":1000000,
"Bwd Header Len":20,
"Init Bwd Win Byts":0,
"Subflow Fwd Byts":3000,
"Fwd Pkt Len Max":120,
"Pkt Len Max":150,
"Fwd Seg Size Avg":100,
"Pkt Size Avg":110,
"TotLen Fwd Pkts":3000,
"Bwd Pkt Len Mean":120,
"Fwd Pkt Len Mean":100,
"TotLen Bwd Pkts":3500,
"Tot Fwd Pkts":30,
"Pkt Len Mean":110,
"Bwd Seg Size Avg":120,
"Pkt Len Var":50,
"Subflow Bwd Byts":3500,
"Bwd Pkt Len Max":200,
"Subflow Fwd Pkts":30,
"Pkt Len Std":5,
"Subflow Bwd Pkts":35,
"Tot Bwd Pkts":35,
"Flow IAT Std":1000000,
"Fwd Pkt Len Std":10,
"Bwd Pkt Len Std":10,
"Flow Byts/s":1000,
"Bwd IAT Tot":10000000,
"Bwd IAT Max":5000000,
"Fwd IAT Std":900000,
"Bwd IAT Mean":4000000,
"Fwd Act Data Pkts":30,
"Bwd IAT Std":500000,
"Bwd IAT Min":100000,
"ECE Flag Cnt":0,
"RST Flag Cnt":0,
"Fwd Pkt Len Min":80,
"ACK Flag Cnt":1,
"Bwd Pkt Len Min":80,
"Idle Max":8000000,
"Down/Up Ratio":1.2,
"Idle Mean":4000000,
"Idle Min":1000000,
"Pkt Len Min":80,
"PSH Flag Cnt":0,
"URG Flag Cnt":0,
"Active Max":200000,
"Active Min":100000,
"Active Mean":150000,
"Idle Std":200000,
"Active Std":50000,
"Fwd PSH Flags":0,
"SYN Flag Cnt":1,
"FIN Flag Cnt":0,
"Fwd Byts/b Avg":0,
"Fwd URG Flags":0
}

flows = [flow_ddos, flow_slow_scan, flow_exfiltration,flow_c2_beacon, flow_data_exfil, flow_reverse_shell]

def generate_flow():

    flow = dict(flow)

    # randomize some fields
    flow["Flow Duration"] = random.randint(1000, 1000000)
    flow["Flow Pkts/s"] = random.uniform(100, 2000)
    flow["Flow Byts/s"] = random.uniform(100, 10000)
    flow["Tot Fwd Pkts"] = random.randint(2, 20)
    flow["Tot Bwd Pkts"] = random.randint(0, 10)

    # 10% anomaly traffic
    if random.random() < 0.1:

        flow["Flow Duration"] = random.randint(5_000_000, 10_000_000)
        flow["Flow Pkts/s"] = random.uniform(5000, 50000)
        flow["Flow Byts/s"] = random.uniform(10000, 200000)

    return flow


def main():

    latencies = []
    alerts = 0

    print("\nSending flows to IDS server...\n")

    start = time.time()

    for flow in flows:

        t0 = time.time()

        r = requests.post(
            SERVER_URL,
            json={
                "features": flow,
                "meta": None
            }
        )

        latency = time.time() - t0
        latencies.append(latency)

        if r.status_code != 200:
            print("ERROR:", r.status_code, r.text)
            exit

        result = r.json()

        if result["alert"] is not None:
            alerts += 1

    end = time.time()

    print("\n========== RESULTS ==========\n")

    print("Total flows:", TOTAL_REQUESTS)
    print("Total alerts:", alerts)

    print("\nLatency")
    print("Mean:", round(statistics.mean(latencies)*1000,2),"ms")
    print("Median:", round(statistics.median(latencies)*1000,2),"ms")
    print("Max:", round(max(latencies)*1000,2),"ms")

    duration = end-start
    print("\nThroughput:", round(TOTAL_REQUESTS/duration,2),"flows/sec")

    print("\n=============================\n")


if __name__ == "__main__":
    main()