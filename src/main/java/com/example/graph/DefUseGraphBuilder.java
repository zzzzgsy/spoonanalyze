package com.example.graph;

import spoon.reflect.CtModel;
import spoon.reflect.code.CtAssignment;
import spoon.reflect.code.CtExpression;
import spoon.reflect.code.CtInvocation;
import spoon.reflect.code.CtVariableRead;
import spoon.reflect.visitor.filter.TypeFilter;
import java.util.*;

public class DefUseGraphBuilder {
    public static void buildDefUseGraph(CtModel model, DataFlowGraph graph) {
        model.getAllTypes().forEach(type -> {
            String className = type.getQualifiedName();
            type.getMethods().forEach(method -> {
                String methodName = method.getSimpleName();

                // 1. 定义点（局部变量、赋值、字段写入）
                method.getElements(new TypeFilter<>(CtAssignment.class)).forEach(assign -> {
                    String varName = assign.getAssigned().toString();
                    int line = assign.getPosition().getLine();
                    DataFlowGraph.VariableNode def = new DataFlowGraph.VariableNode(varName, methodName, className,
                            line);

                    // 2. 使用点（RHS中所有变量读取）
                    assign.getAssignment().getElements(new TypeFilter<>(CtVariableRead.class)).forEach(read -> {
                        String useName = read.toString();
                        int useLine = read.getPosition().getLine();
                        DataFlowGraph.VariableNode use = new DataFlowGraph.VariableNode(useName, methodName, className,
                                useLine);
                        graph.addEdge(def, use);
                    });
                });

                // 3. 其他显式使用（如日志调用参数中的变量读取）
                method.getElements(new TypeFilter<>(CtInvocation.class)).forEach(inv -> {
                    // 显式指定类型参数
                    List<CtExpression<?>> arguments = inv.getArguments();
                    for (CtExpression<?> arg : arguments) {
                        if (arg instanceof CtVariableRead) {
                            String varName = arg.toString();
                            int line = arg.getPosition().getLine();
                            DataFlowGraph.VariableNode use = new DataFlowGraph.VariableNode(varName, methodName,
                                    className, line);
                            graph.getDefs(use).forEach(def -> graph.addEdge(def, use));
                        }
                    }
                });
            });
        });
    }
}
