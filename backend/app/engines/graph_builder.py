import networkx as nx
import json

def build_graph():
    G = nx.Graph()

    with open("dataset/network_logs.json") as f:
        logs = json.load(f)

    for entry in logs:
        src = entry["source"]
        dst = entry["destination"]
        G.add_edge(src, dst)

    return G
