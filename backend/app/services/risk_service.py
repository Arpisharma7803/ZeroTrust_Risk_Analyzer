from app.engines.graph_builder import build_graph
from app.engines.risk_engine import calculate_risk

def analyze_risk():
    graph = build_graph()
    return calculate_risk(graph)