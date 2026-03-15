import networkx as nx

def find_lateral_paths(graph):

    paths = []

    nodes = list(graph.nodes())

    for i in range(len(nodes)):
        for j in range(i+1, len(nodes)):
            try:
                path = nx.shortest_path(graph, nodes[i], nodes[j])
                paths.append(path)
            except:
                pass

    return paths