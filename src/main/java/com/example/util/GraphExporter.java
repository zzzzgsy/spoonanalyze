package com.example.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GraphExporter {
    /**
     * 将切片路径转为 DOT 格式（Graphviz）
     * 
     * @param graphName 图名称
     * @param pathNodes 路径节点列表（按顺序）
     * @return DOT 字符串
     */
    public static String toDot(String graphName, List<String> pathNodes) {
        StringBuilder sb = new StringBuilder();
        sb.append("digraph ").append(sanitize(graphName)).append(" {\n");

        // 为每个节点分配唯一ID
        Map<String, String> nodeIds = new HashMap<>();
        int id = 0;

        for (String node : pathNodes) {
            if (!nodeIds.containsKey(node)) {
                nodeIds.put(node, "n" + id++);
                sb.append("  ").append(nodeIds.get(node))
                        .append(" [label=\"").append(escape(node)).append("\"];\n");
            }
        }

        for (int i = 0; i < pathNodes.size() - 1; i++) {
            String from = nodeIds.get(pathNodes.get(i));
            String to = nodeIds.get(pathNodes.get(i + 1));
            sb.append("  ").append(from).append(" -> ").append(to).append(";\n");
        }

        sb.append("}\n");
        return sb.toString();
    }

    private static String sanitize(String name) {
        return name.replaceAll("[^a-zA-Z0-9_]", "_");
    }

    private static String escape(String label) {
        return label.replace("\"", "\\\"").replace("\n", "\\n");
    }
}
