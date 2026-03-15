def calculate_risk(graph):

    risk_scores = {}

    for node in graph.nodes():
        connections = len(list(graph.neighbors(node)))
        risk_scores[node] = connections

    return risk_scores