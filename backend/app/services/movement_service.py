from app.engines.graph_builder import build_graph
from app.engines.lateral_movement import find_lateral_paths

def analyze_movement():
    graph = build_graph()
    return find_lateral_paths(graph)