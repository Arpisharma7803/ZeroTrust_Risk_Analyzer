import json
import os

RISK_FACTORS = {
    "failed_auth":     {"weight": 30, "label": "Multiple failed auths"},
    "unusual_time":    {"weight": 25, "label": "Unusual login times"},
    "high_traffic":    {"weight": 20, "label": "High outbound traffic"},
    "lateral_spike":   {"weight": 15, "label": "Lateral conn spike"},
    "port_scan":       {"weight": 10, "label": "Port scan detected"},
}

def calculate_risk(graph):
    risk_scores = {}

    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(base_dir, "..", "..", "dataset", "network_logs.json")

    try:
        with open(log_path) as f:
            logs = json.load(f)
    except:
        logs = []

    # Count connections per node from logs
    connection_count = {}
    for entry in logs:
        src = entry.get("source", "")
        connection_count[src] = connection_count.get(src, 0) + 1

    for node in graph.nodes():
        connections = len(list(graph.neighbors(node)))
        log_hits = connection_count.get(node, 0)

        # Base score from connections
        score = min(connections * 15, 60)

        # Add log-based risk
        score += min(log_hits * 2, 30)

        # Add degree centrality bonus
        degree = graph.degree(node)
        if degree > 3:
            score += 10

        score = max(10, min(int(score), 99))

        # Determine factors
        factors = []
        if connections > 2:
            factors.append(RISK_FACTORS["lateral_spike"]["label"])
        if log_hits > 3:
            factors.append(RISK_FACTORS["failed_auth"]["label"])
        if degree > 3:
            factors.append(RISK_FACTORS["high_traffic"]["label"])
        if score > 70:
            factors.append(RISK_FACTORS["unusual_time"]["label"])
        if not factors:
            factors.append("Normal baseline activity")

        risk_scores[node] = {
            "score": score,
            "factors": factors
        }

    return risk_scores