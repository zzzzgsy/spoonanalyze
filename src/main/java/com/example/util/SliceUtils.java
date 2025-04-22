package com.example.util;

import java.util.LinkedList;
import java.util.Queue;

import com.example.graph.DataFlowGraph;
import java.util.*;

public class SliceUtils {
    public static Set<DataFlowGraph.VariableNode> backwardSlice(DataFlowGraph graph, DataFlowGraph.VariableNode sink) {
        Set<DataFlowGraph.VariableNode> result = new HashSet<>();
        Queue<DataFlowGraph.VariableNode> worklist = new LinkedList<>();
        worklist.add(sink);

        while (!worklist.isEmpty()) {
            DataFlowGraph.VariableNode current = worklist.poll();
            if (result.add(current)) {
                Set<DataFlowGraph.VariableNode> defs = graph.getDefs(current);
                worklist.addAll(defs);
            }
        }
        return result;
    }

}
