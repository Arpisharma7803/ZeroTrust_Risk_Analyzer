from app.engines.risk_engine import calculate_risk
from app.services.graph_service import get_graph

def analyze_risk():
    graph = get_graph()
    risk_scores = calculate_risk(graph)

    nodes = []
    for node_id, data in risk_scores.items():
        nodes.append({
            "id":      node_id,
            "score":   data["score"],
            "factors": data["factors"]
        })

    nodes.sort(key=lambda x: x["score"], reverse=True)
    return nodes