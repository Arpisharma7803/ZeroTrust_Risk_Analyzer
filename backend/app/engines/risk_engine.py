import json
import os
from datetime import datetime

def calculate_risk(graph):
    risk_scores = {}

    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(base_dir, "..", "..", "dataset", "network_logs.json")

    try:
        with open(log_path) as f:
            logs = json.load(f)
    except:
        logs = []

    # Analyze each log entry
    failed_count    = {}
    attempt_count   = {}
    odd_hour_count  = {}
    connection_count = {}

    for entry in logs:
        src    = entry.get("source", "")
        status = entry.get("status", "success")
        attempts = entry.get("attempts", 1)
        timestamp = entry.get("timestamp", "")

        connection_count[src] = connection_count.get(src, 0) + 1

        if status == "failed":
            failed_count[src] = failed_count.get(src, 0) + 1
            attempt_count[src] = attempt_count.get(src, 0) + attempts

        # Detect odd hour access (before 6am or after 10pm)
        try:
            hour = datetime.fromisoformat(timestamp).hour
            if hour < 6 or hour > 22:
                odd_hour_count[src] = odd_hour_count.get(src, 0) + 1
        except:
            pass

    for node in graph.nodes():
        score   = 10
        factors = []

        connections = len(list(graph.neighbors(node)))
        fails       = failed_count.get(node, 0)
        attempts    = attempt_count.get(node, 0)
        odd_hours   = odd_hour_count.get(node, 0)
        log_hits    = connection_count.get(node, 0)

        # Factor 1 — Failed authentications
        if fails > 5:
            score += 30
            factors.append("Multiple failed auths")
        elif fails > 2:
            score += 15
            factors.append("Some failed auths")

        # Factor 2 — Odd hour access
        if odd_hours > 3:
            score += 25
            factors.append("Unusual login times")
        elif odd_hours > 0:
            score += 10
            factors.append("After-hours access")

        # Factor 3 — High attempt count
        if attempts > 10:
            score += 20
            factors.append("High outbound traffic")

        # Factor 4 — Many lateral connections
        if connections > 3:
            score += 15
            factors.append("Lateral conn spike")
        elif connections > 1:
            score += 5

        # Factor 5 — High log activity
        if log_hits > 5:
            score += 10
            factors.append("Port scan detected")

        score = max(10, min(int(score), 99))
        if not factors:
            factors.append("Normal baseline activity")

        risk_scores[node] = {
            "score":   score,
            "factors": factors
        }

    return risk_scores
