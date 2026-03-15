import networkx as nx

TECHNIQUES = [
    "Pass-the-Hash",
    "Token Relay",
    "Credential Stuffing",
    "ARP Spoofing",
    "Port Scanning"
]

def find_lateral_paths(graph):
    paths = []
    nodes = list(graph.nodes())

    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            try:
                path = nx.shortest_path(graph, nodes[i], nodes[j])
                if len(path) >= 2:
                    risk = max(30, 100 - (len(path) * 10) + 
                              (graph.degree(nodes[i]) * 5))
                    risk = min(risk, 99)
                    technique = TECHNIQUES[
                        (i + j) % len(TECHNIQUES)
                    ]
                    paths.append({
                        "path": path,
                        "risk": risk,
                        "method": technique,
                        "hops": len(path) - 1
                    })
            except:
                pass

    paths.sort(key=lambda x: x["risk"], reverse=True)
    return paths[:10]