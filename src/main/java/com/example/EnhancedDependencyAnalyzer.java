package com.example;

import soot.*;
import soot.toolkits.graph.*;
import soot.toolkits.scalar.*;

import static com.example.enhancement.LogEnhancement.*;

import java.util.*;
import soot.options.Options;
import spoon.reflect.code.CtStatement;
import spoon.reflect.declaration.CtMethod;
import spoon.reflect.declaration.CtParameter;

public class EnhancedDependencyAnalyzer {
    // Soot初始化
    static {
        soot.G.reset();

        Options.v().set_keep_line_number(true);
        Options.v().set_whole_program(true);
        Options.v().setPhaseOption("jb", "use-original-names:true");
    }

    // 使用Soot进行精准数据流分析
    public static Set<String> performSootDataFlowAnalysis(String className, String methodName, int lineNumber) {
        // 后向切片分析
        class MyBackwardAnalysis extends BackwardFlowAnalysis<Unit, FlowSet<Local>> {

            public MyBackwardAnalysis(UnitGraph graph) {
                super(graph);
            }

            @Override
            protected void flowThrough(FlowSet<Local> in, Unit unit, FlowSet<Local> out) {
                in.copy(out);
                for (ValueBox useBox : unit.getUseBoxes()) {
                    Value v = useBox.getValue();
                    if (v instanceof Local) {
                        out.add((Local) v);
                    }
                }
                for (ValueBox defBox : unit.getDefBoxes()) {
                    Value v = defBox.getValue();
                    if (v instanceof Local) {
                        out.remove((Local) v);
                    }
                }
            }

            @Override
            protected FlowSet<Local> newInitialFlow() {
                return new ArraySparseSet<>();
            }

            @Override
            protected void merge(FlowSet<Local> in1, FlowSet<Local> in2, FlowSet<Local> out) {
                in1.union(in2, out);
            }

            @Override
            protected void copy(FlowSet<Local> source, FlowSet<Local> dest) {
                source.copy(dest);
            }

            // 可以在构造函数中直接运行分析
            public void run() {
                doAnalysis();
            }
        }

        Set<String> variables = new HashSet<>();

        // 加载类和方法
        SootClass sootClass = Scene.v().loadClassAndSupport(className);
        SootMethod method = sootClass.getMethodByName(methodName);

        // 构建控制流图
        Body body = method.retrieveActiveBody();
        UnitGraph cfg = new BriefUnitGraph(body);

        // analysis.doAnalysis();
        MyBackwardAnalysis analysis = new MyBackwardAnalysis(cfg);
        analysis.run();

        // 获取目标行号的Unit
        for (Unit unit : body.getUnits()) {
            if (unit.getJavaSourceStartLineNumber() == lineNumber) {
                FlowSet<Local> flowSet = analysis.getFlowAfter(unit);
                for (Local local : flowSet) {
                    variables.add(local.getName());
                }
                break;
            }
        }

        return variables;
    }

    // 结合Spoon和Soot的分析
    public static Set<String> enhancedExtractVariables(CtMethod<?> method, CtStatement failStmt) {
        Set<String> variables = new HashSet<>();

        // 1. 使用Soot进行精准数据流分析
        String className = method.getDeclaringType().getQualifiedName();
        String methodName = method.getSimpleName();
        int lineNumber = failStmt.getPosition().getLine();

        try {
            variables.addAll(performSootDataFlowAnalysis(className, methodName, lineNumber));
        } catch (Exception e) {
            // 回退到Spoon的简单分析
            variables.addAll(extractVariablesBySlice(method, failStmt));
        }

        // 2. 添加方法参数
        for (CtParameter<?> p : method.getParameters()) {
            variables.add(p.getSimpleName());
        }

        return variables;
    }
}