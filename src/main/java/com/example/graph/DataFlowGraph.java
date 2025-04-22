package com.example.graph;

import java.util.*;

public class DataFlowGraph {

    public static class VariableNode {
        public String name;
        public String method;
        public String clazz;
        public int line;

        public VariableNode(String name, String method, String clazz, int line) {
            this.name = name;
            this.method = method;
            this.clazz = clazz;
            this.line = line;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            VariableNode that = (VariableNode) o;
            return line == that.line &&
                    Objects.equals(name, that.name) &&
                    Objects.equals(method, that.method) &&
                    Objects.equals(clazz, that.clazz);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, method, clazz, line);
        }

        @Override
        public String toString() {
            return clazz + "." + method + ":" + name + "@" + line;
        }
    }

    private final Map<VariableNode, Set<VariableNode>> edges = new HashMap<>();
    private final Map<VariableNode, Set<VariableNode>> reverseEdges = new HashMap<>();

    public void addEdge(VariableNode from, VariableNode to) {
        edges.computeIfAbsent(from, k -> new HashSet<>()).add(to);
        reverseEdges.computeIfAbsent(to, k -> new HashSet<>()).add(from);
    }

    public Set<VariableNode> getDefs(VariableNode use) {
        return reverseEdges.getOrDefault(use, Collections.emptySet());
    }

    public Set<VariableNode> getUses(VariableNode def) {
        return edges.getOrDefault(def, Collections.emptySet());
    }

    public Set<VariableNode> getAllNodes() {
        Set<VariableNode> all = new HashSet<>(edges.keySet());
        all.addAll(reverseEdges.keySet());
        return all;
    }
}
