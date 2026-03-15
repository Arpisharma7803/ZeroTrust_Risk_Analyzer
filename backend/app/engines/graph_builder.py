import networkx as nx
import json
import os

def build_graph():
    G = nx.DiGraph()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(base_dir, "..", "..", "dataset", "network_logs.json")

    with open(log_path) as f:
        logs = json.load(f)

    for entry in logs:
        src = entry["source"]
        dst = entry["destination"]
        G.add_edge(src, dst, 
                   protocol=entry.get("protocol", "TCP"),
                   port=entry.get("port", 80))

    return G