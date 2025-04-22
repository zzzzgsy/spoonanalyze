package com.example.analyzer;

import spoon.Launcher;
import spoon.reflect.CtModel;
import spoon.reflect.code.*;
import spoon.reflect.declaration.*;
import spoon.reflect.reference.*;
import spoon.reflect.visitor.filter.*;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import com.example.detector.SemanticAnalyzer;
import com.example.detector.SensitiveDetector;
import com.example.graph.DataFlowGraph;
import com.example.graph.DefUseGraphBuilder;
import com.example.util.GraphExporter;
import com.example.util.JsonUtils;
import static com.example.detector.LogDetector.*;
import static com.example.detector.SensitiveDetector.*;

public class EnhancedAnalyzer {
    private final static DataFlowGraph dataFlowGraph = new DataFlowGraph();

    // 使用Wrapper类来精确追踪变量和字段
    private static class VariableWrapper {
        CtVariableReference<?> ref;
        String context; // 方法或类上下文
        boolean isField;

        VariableWrapper(CtVariable<?> var) {
            this.ref = var.getReference();
            this.context = var.getParent(CtMethod.class) != null ? var.getParent(CtMethod.class).getSimpleName()
                    : var.getParent(CtType.class).getQualifiedName();
            this.isField = var instanceof CtField;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (!(o instanceof VariableWrapper))
                return false;
            VariableWrapper that = (VariableWrapper) o;
            return ref.equals(that.ref) && context.equals(that.context);
        }

        @Override
        public int hashCode() {
            return Objects.hash(ref, context);
        }
    }

    public static class FieldInfo {
        public String name;
        public boolean unsafe; // true 表示在 unsafeInitializations 中

        public FieldInfo(String name, boolean unsafe) {
            this.name = name;
            this.unsafe = unsafe;
        }
    }

    // 改进的敏感类信息记录
    public static class SensitiveClassInfo {
        public String className;
        public Set<String> securityMethods = new HashSet<>();
        public List<FieldInfo> sensitiveFields = new ArrayList<>();
        // 新增：字段赋值和使用点记录
        public Map<String, Set<FieldUsage>> fieldUsages = new HashMap<>();
        public List<SensitiveLocalVariable> sensitiveLocals = new ArrayList<>();
        public List<FlowRecord> flowRecords = new ArrayList<>();
        public String dotGraph; // DOT 图结构

    }

    public static class FieldUsage {
        public String methodName;
        public int lineNumber;
        public boolean isWrite; // true表示赋值，false表示使用

        public FieldUsage(String methodName, int lineNumber, boolean isWrite) {
            this.methodName = methodName;
            this.lineNumber = lineNumber;
            this.isWrite = isWrite;
        }
    }

    public static class SensitiveLocalVariable {
        String variableName;
        String methodName;
        int lineNumber;
        boolean unsafe;

        // 添加构造函数
        public SensitiveLocalVariable(String variableName, String methodName, int lineNumber, boolean unsafe) {
            this.variableName = variableName;
            this.methodName = methodName;
            this.lineNumber = lineNumber;
            this.unsafe = unsafe;
        }

        // 可选：添加getter方法
        public String getVariableName() {
            return variableName;
        }

        public String getMethodName() {
            return methodName;
        }

        public int getLineNumber() {
            return lineNumber;
        }
    }

    public static class FlowRecord {
        public String methodName;
        public int lineNumber;
        public String path;

        public FlowRecord(String methodName, int lineNumber, String path) {
            this.methodName = methodName;
            this.lineNumber = lineNumber;
            this.path = path;
        }
    }

    // 其他原有记录类保持不变...

    // 1. 改进的数据流分析 - 使用调用图构建和更精确的变量追踪
    public static void analyzeDataFlowToLog(CtElement source, CtType<?> containerClass,
            SensitiveClassInfo info, Set<Object> visited, String path, CtModel model) {
        // 添加控制依赖信息（如果尚未包含）
        List<String> ctrlDeps = ControlDependencyAnalyzer.getControlDependencies(source);
        if (!ctrlDeps.isEmpty() && !path.contains("ControlDependency")) {
            path = "ControlDependency[" + String.join(" -> ", ctrlDeps) + "]" + " -> " + path;
        }
        // 使用Wrapper代替直接CtElement防止重复访问
        Object visitKey = getVisitKey(source);
        if (visited.contains(visitKey))
            return;
        visited.add(visitKey);

        // 构建调用图进行分析
        analyzeMethodCalls(source, containerClass, info, visited, path, model);

        // 新增：处理字段赋值链
        if (source instanceof CtField) {
            analyzeFieldAccesses((CtField<?>) source, containerClass, info, visited, path, model);
        }

        // 新增：处理异常流
        analyzeExceptionFlows(source, containerClass, info, visited, path);

        if (!info.flowRecords.isEmpty()) {
            // 提取所有 path 字段
            List<String> paths = info.flowRecords.stream()
                    .map(record -> record.path)
                    .collect(Collectors.toList());
            // 生成 DOT 图
            info.dotGraph = GraphExporter.toDot(
                    info.className,
                    paths);
        }
    }

    private static Object getVisitKey(CtElement element) {
        if (element instanceof CtVariable) {
            return new VariableWrapper((CtVariable<?>) element);
        }
        return element; // 对于其他元素直接使用对象作为key
    }

    // 2. 改进的方法调用分析（使用调用图）
    private static void analyzeMethodCalls(CtElement source, CtType<?> containerClass,
            SensitiveClassInfo info, Set<Object> visited, String path, CtModel model) {

        // 获取容器类中的所有方法调用
        List<CtInvocation<?>> invocations = containerClass.getElements(new TypeFilter<>(CtInvocation.class));

        // 获取source的变量引用（如果是变量）
        Set<CtVariableReference<?>> targetRefs = getVariableReferences(source);

        for (CtInvocation<?> inv : invocations) {
            // 检查是否是日志调用
            if (isLoggingOrPrintInvocation(inv)) {
                checkArgumentsForSensitiveData(inv, targetRefs, info, path, model);
            }

            // 改进的跨方法分析
            analyzeCrossMethodDataFlow(source, inv, info, visited, path, model);
        }
    }

    // 3. 新增字段访问分析
    private static void analyzeFieldAccesses(CtField<?> field, CtType<?> containerClass,
            SensitiveClassInfo info, Set<Object> visited, String path, CtModel model) {

        // 记录字段的所有使用点
        recordFieldUsages(field, containerClass, info);

        // 查找所有对该字段的读写操作
        List<CtFieldAccess<?>> accesses = containerClass.getElements(new TypeFilter<>(CtFieldAccess.class));
        for (CtFieldAccess<?> access : accesses) {
            if (access.getVariable().equals(field.getReference())) {
                // 如果是赋值操作，追踪赋值来源
                if (access.getParent() instanceof CtAssignment) {
                    CtAssignment<?, ?> assignment = (CtAssignment<?, ?>) access.getParent();
                    analyzeDataFlowToLog(assignment.getAssignment(), containerClass, info,
                            visited, path + " -> field_assignment:" + field.getSimpleName(), model);
                }
                // 如果是读取操作，继续追踪使用点
                else {
                    analyzeDataFlowToLog(access, containerClass, info,
                            visited, path + " -> field_read:" + field.getSimpleName(), model);
                }
            }
        }
    }

    // 4. 新增异常流分析
    private static void analyzeExceptionFlows(CtElement source, CtType<?> containerClass,
            SensitiveClassInfo info, Set<Object> visited, String path) {

        // 查找所有可能抛出异常的语句
        List<CtThrow> throwStatements = containerClass.getElements(new TypeFilter<>(CtThrow.class));
        for (CtThrow throwStmt : throwStatements) {
            // 检查抛出的异常是否包含敏感数据
            if (containsVariableReference(throwStmt.getThrownExpression(), getVariableReferences(source))) {
                // 查找对应的catch块和日志记录
                analyzeExceptionHandling(throwStmt, source, containerClass, info, visited, path);
            }
        }
    }

    // 辅助方法：获取元素关联的变量引用
    private static Set<CtVariableReference<?>> getVariableReferences(CtElement element) {
        Set<CtVariableReference<?>> refs = new HashSet<>();
        if (element instanceof CtVariable) {
            refs.add(((CtVariable<?>) element).getReference());
        } else if (element instanceof CtVariableAccess) {
            refs.add(((CtVariableAccess<?>) element).getVariable());
        } else if (element instanceof CtFieldAccess) {
            refs.add(((CtFieldAccess<?>) element).getVariable());
        }
        // 对于方法，收集参数..返回值？？？
        else if (element instanceof CtMethod) {
            CtMethod<?> method = (CtMethod<?>) element;
            method.getParameters().forEach(p -> refs.add(p.getReference())); // ✅ 只添加参数引用

        }
        return refs;
    }

    // 辅助方法：检查参数是否包含敏感数据
    private static void checkArgumentsForSensitiveData(CtInvocation<?> inv,
            Set<CtVariableReference<?>> targetRefs, SensitiveClassInfo info, String path, CtModel model) {

        for (CtExpression<?> arg : inv.getArguments()) {
            if (containsVariableReference(arg, targetRefs)) {
                // 已经记录日志位置和数据流路径
                // 只做一次添加
                info.flowRecords.add(
                        new FlowRecord(
                                inv.getParent(CtMethod.class) != null
                                        ? inv.getParent(CtMethod.class).getSimpleName()
                                        : "unknown",
                                inv.getPosition() != null ? inv.getPosition().getLine() : -1,
                                path + " -> " + inv.toString()));

                // 【新增】进行 backward slicing
                if (arg instanceof CtVariableRead) {
                    CtVariableRead<?> varRead = (CtVariableRead<?>) arg;
                    String varName = varRead.toString();
                    int line = varRead.getPosition().getLine();
                    String methodName = inv.getParent(CtMethod.class) != null
                            ? inv.getParent(CtMethod.class).getSimpleName()
                            : "unknown";
                    String clazz = inv.getParent(CtType.class).getQualifiedName();
                    DataFlowGraph.VariableNode sink = new DataFlowGraph.VariableNode(varName, methodName, clazz, line);

                    Set<DataFlowGraph.VariableNode> slice = backwardSlice(dataFlowGraph, sink);
                    // 你可以把 slice 转成字符串或者做进一步的检查与记录
                    System.out.println("Backward slice for sink " + sink + ": " + slice);
                    // 如果 slice 中包含敏感变量的定义，则记录提示
                    // （这里假设你有一份敏感变量列表，可比较 node.name 是否等于敏感字段/变量名）
                }
            }
        }
    }

    // 辅助方法：检查表达式是否包含目标变量引用
    private static boolean containsVariableReference(CtExpression<?> expr,
            Set<CtVariableReference<?>> targetRefs) {

        if (expr == null)
            return false;

        // 检查变量读取
        if (expr instanceof CtVariableRead) {
            return targetRefs.contains(((CtVariableRead<?>) expr).getVariable());
        }
        // 检查字段访问
        else if (expr instanceof CtFieldAccess) {
            return targetRefs.contains(((CtFieldAccess<?>) expr).getVariable());
        }
        // 递归检查复杂表达式
        else {
            return expr.getElements(new AbstractFilter<CtElement>(CtElement.class) {
                @Override
                public boolean matches(CtElement element) {
                    if (element instanceof CtVariableRead) {
                        return targetRefs.contains(((CtVariableRead<?>) element).getVariable());
                    }
                    return false;
                }
            }).size() > 0;
        }
    }

    // 改进的跨方法分析
    private static void analyzeCrossMethodDataFlow(CtElement source, CtInvocation<?> inv,
            SensitiveClassInfo info, Set<Object> visited, String path, CtModel model) {

        CtExecutableReference<?> execRef = inv.getExecutable();
        if (execRef != null && execRef.getDeclaration() != null) {
            CtExecutable<?> callee = execRef.getDeclaration();

            // 处理方法调用
            if (callee instanceof CtMethod) {
                CtMethod<?> method = (CtMethod<?>) callee;

                // 1. 分析参数传递
                analyzeParameterPassing(source, inv, method, info, visited, path, model);

                // 2. 分析返回值
                if (method.getType() != null && !method.getType().equals(method.getFactory().Type().VOID_PRIMITIVE)) {
                    analyzeReturnValueFlow(source, method, info, visited, path, model);
                }
            }
        }
    }

    // 分析参数传递
    private static void analyzeParameterPassing(CtElement source, CtInvocation<?> inv,
            CtMethod<?> method, SensitiveClassInfo info, Set<Object> visited, String path, CtModel model) {

        List<CtExpression<?>> actualArgs = inv.getArguments();
        List<CtParameter<?>> params = method.getParameters();

        for (int i = 0; i < Math.min(actualArgs.size(), params.size()); i++) {
            CtExpression<?> actual = actualArgs.get(i);
            CtParameter<?> formal = params.get(i);

            if (containsVariableReference(actual, getVariableReferences(source))) {
                analyzeDataFlowToLog(
                        formal,
                        method.getParent(CtType.class),
                        info,
                        visited,
                        path + " -> param:" + method.getSimpleName() + "(" + formal.getSimpleName() + ")", model);
            }
        }
    }

    // 分析返回值流
    private static void analyzeReturnValueFlow(CtElement source, CtMethod<?> method,
            SensitiveClassInfo info, Set<Object> visited, String path, CtModel model) {

        // 查找方法体中的所有return语句
        List<CtReturn<?>> returns = method.getElements(new TypeFilter<>(CtReturn.class));
        for (CtReturn<?> ret : returns) {
            if (containsVariableReference(ret.getReturnedExpression(), getVariableReferences(source))) {
                // 追踪方法返回值的使用
                analyzeMethodReturnUses(method, info, visited, path, model);
            }
        }
    }

    // 记录字段使用情况
    private static void recordFieldUsages(CtField<?> field, CtType<?> containerClass,
            SensitiveClassInfo info) {

        String fieldName = field.getSimpleName();
        info.fieldUsages.putIfAbsent(fieldName, new HashSet<>());

        // 查找字段读取
        containerClass.getElements(new AbstractFilter<CtFieldRead<?>>(CtFieldRead.class) {
            @Override
            public boolean matches(CtFieldRead<?> fieldRead) {
                if (fieldRead.getVariable().equals(field.getReference())) {
                    info.fieldUsages.get(fieldName).add(new FieldUsage(
                            fieldRead.getParent(CtMethod.class) != null
                                    ? fieldRead.getParent(CtMethod.class).getSimpleName()
                                    : "static_block",
                            fieldRead.getPosition().getLine(),
                            false));
                }
                return false;
            }
        });

        // 查找字段写入
        containerClass.getElements(new AbstractFilter<CtFieldWrite<?>>(CtFieldWrite.class) {
            @Override
            public boolean matches(CtFieldWrite<?> fieldWrite) {
                if (fieldWrite.getVariable().equals(field.getReference())) {
                    info.fieldUsages.get(fieldName).add(new FieldUsage(
                            fieldWrite.getParent(CtMethod.class) != null
                                    ? fieldWrite.getParent(CtMethod.class).getSimpleName()
                                    : "static_block",
                            fieldWrite.getPosition().getLine(),
                            true));
                }
                return false;
            }
        });
    }

    // 分析异常处理中的日志记录
    // 或者保持流式API但使用方法引用正确的方式
    private static void analyzeExceptionHandling(CtThrow throwStmt, CtElement source,
            CtType<?> containerClass, SensitiveClassInfo info, Set<Object> visited, String path) {

        // 查找包含throw语句的try块
        CtTry tryBlock = throwStmt.getParent(CtTry.class);
        if (tryBlock != null) {
            // 检查catch块中的日志记录
            for (CtCatch catchBlock : tryBlock.getCatchers()) {
                catchBlock.getElements(new TypeFilter<>(CtInvocation.class)).stream()
                        .filter(inv -> isLoggingOrPrintInvocation(inv)) // 使用lambda表达式替代方法引用
                        .forEach(inv -> {
                            if (containsVariableReference((CtExpression<?>) catchBlock.getParameter().getReference(),
                                    getVariableReferences(source))) {
                                // 只做一次添加
                                info.flowRecords.add(new FlowRecord(
                                        // 哪个方法里打印
                                        catchBlock.getParent(CtMethod.class) != null
                                                ? catchBlock.getParent(CtMethod.class).getSimpleName()
                                                : "unknown",
                                        // 打印所在行号
                                        inv.getPosition() != null ? inv.getPosition().getLine() : -1,
                                        // 完整切片路径 + 日志调用源码
                                        path
                                                + " -> catch:"
                                                + catchBlock.getParameter().getSimpleName()
                                                + " -> "
                                                + inv.toString()));
                            }
                        });
            }
        }
    }

    // 分析返回值的使用
    private static void analyzeMethodReturnUses(CtMethod<?> method, SensitiveClassInfo info,
            Set<Object> visited, String path, CtModel model) {

        // 查找方法的所有调用点
        method.getReference().getDeclaringType().getElements(new TypeFilter<>(CtInvocation.class))
                .stream()
                .filter(inv -> inv.getExecutable().equals(method.getReference()))
                .forEach(inv -> {
                    // 如果返回值被用于日志调用
                    if (inv.getParent() instanceof CtVariableRead || inv.getParent() instanceof CtFieldAccess) {
                        analyzeDataFlowToLog(inv.getParent(), method.getParent(CtType.class),
                                info, visited, path + " -> return_value_usage", model);
                    }
                });
    }

    // ---------------------- 总体模型分析 ----------------------
    public static List<SensitiveClassInfo> analyzeModel(CtModel model) {
        List<SensitiveClassInfo> result = Collections.synchronizedList(new ArrayList<>());

        // 并行处理类型分析以提高性能
        model.getAllTypes().parallelStream().forEach(type -> {
            SensitiveClassInfo info = new SensitiveClassInfo();
            info.className = type.getQualifiedName();

            // 1. 分析方法
            analyzeMethods(type, info, model);

            // 2. 分析字段
            analyzeFields(type, info, model);

            // 3. 分析局部变量
            analyzeLocalVariables(type, info, model);

            // 只保留包含敏感信息的类
            if (!info.sensitiveFields.isEmpty() || !info.sensitiveLocals.isEmpty()) {
                result.add(info);
            }
        });

        return result;
    }

    private static void analyzeMethods(CtType<?> type, SensitiveClassInfo info, CtModel model) {
        type.getMethods().parallelStream().forEach(method -> {
            if (isSecurityRelatedMethod(method) || containsSensitiveSQL(method)) {
                info.securityMethods.add(method.getSimpleName());
                // 使用新的Wrapper防止重复访问
                analyzeDataFlowToLog(method, type, info,
                        Collections.synchronizedSet(new HashSet<>()), method.getSimpleName(), model);
            }
        });
    }

    private static void analyzeFields(CtType<?> type, SensitiveClassInfo info, CtModel model) {
        type.getFields().parallelStream().forEach(field -> {
            if (isSensitiveField(field)) {

                // 使用新的Wrapper防止重复访问
                // 检查字段初始化是否安全
                boolean unsafe = field.getDefaultExpression() != null
                        && !SemanticAnalyzer.isEncryptedOperation(field.getDefaultExpression());
                // 直接 new 一个 FieldInfo，传给 List.add(E)
                info.sensitiveFields.add(new FieldInfo(field.getSimpleName(), unsafe));
                analyzeDataFlowToLog(field, type, info,
                        Collections.synchronizedSet(new HashSet<>()), field.getSimpleName(), model);
            }
        });
    }

    private static void analyzeLocalVariables(CtType<?> type,
            SensitiveClassInfo info,
            CtModel model) {
        type.getMethods().parallelStream().forEach(method -> {
            method.getElements(new TypeFilter<>(CtLocalVariable.class)).stream()
                    .filter(local -> SensitiveDetector.isSensitiveVariable(local))
                    .forEach(local -> {
                        // 1. 先判断这个局部变量初始化时是否“不安全”
                        boolean unsafe = local.getDefaultExpression() != null
                                && !SemanticAnalyzer.isEncryptedOperation(local.getDefaultExpression());
                        // 2. 把 unsafe 标记一起传进去
                        info.sensitiveLocals.add(new SensitiveLocalVariable(
                                local.getSimpleName(),
                                method.getSimpleName(),
                                local.getPosition().getLine(),
                                unsafe));
                        // 3. 原来的数据流分析不变
                        analyzeDataFlowToLog(local,
                                type,
                                info,
                                Collections.synchronizedSet(new HashSet<>()),
                                local.getSimpleName(),
                                model);
                    });
        });
    }

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

    public static void main(String[] args) throws IOException {
        String sourcePath = "C:\\dataset\\SpingBoot\\springboot018_muying-master\\springboot018_muying-master\\muyingshangcheng\\src\\main\\java";
        String outputPath = "C:\\dataset\\spoonanalyze\\output\\information2.json";

        Launcher launcher = new Launcher();
        launcher.addInputResource(sourcePath);
        launcher.getEnvironment().setNoClasspath(true);
        CtModel model = launcher.buildModel();
        DefUseGraphBuilder.buildDefUseGraph(model, dataFlowGraph);
        List<SensitiveClassInfo> detected = analyzeModel(model);
        JsonUtils.writeToJson(detected, outputPath);

        System.out.println("分析完成，已保存至: " + outputPath);
    }

    // 原有的isLoggingOrPrintInvocation、isSecurityRelatedMethod等方法保持不变...
}
