package com.test;

import com.google.gson.*;
import spoon.Launcher;
import spoon.reflect.CtModel;
import spoon.reflect.code.*;
import spoon.reflect.declaration.*;
import spoon.reflect.visitor.filter.TypeFilter;

import static com.example.detector.LogDetector.isLoggingOrPrintInvocation;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;;

public class SensitiveLogTracer {

    static class SensitiveClassInfo {
        String className;
        List<String> sensitiveFields;
        List<String> securityMethods;
    }

    static class LogUsageRecord {
        String className;
        String methodName;
        String sensitiveElement; // field or method name
        String logText;
        int lineNumber;
        String traceType; // direct / param / indirect
    }

    public static void main(String[] args) throws IOException {
        // if (args.length < 3) {
        // System.err.println("用法: java SensitiveLogTracer <json文件路径> <源码路径> <输出路径>");
        // return;
        // }

        String jsonPath = "C:\\dataset\\spoonanalyze\\output\\out.json";
        String sourcePath = "C:\\dataset\\apache-tomcat-9.0.11-master\\java";
        String outputPath = "C:\\dataset\\spoonanalyze\\output\\tomcat2.json";

        List<SensitiveClassInfo> sensitiveClassInfos = loadSensitiveClassInfos(jsonPath);

        Launcher launcher = new Launcher();
        launcher.addInputResource(sourcePath);
        launcher.getEnvironment().setNoClasspath(true);
        CtModel model = launcher.buildModel();

        List<LogUsageRecord> records = new ArrayList<>();

        for (SensitiveClassInfo info : sensitiveClassInfos) {
            CtType<?> clazz = model.getAllTypes().stream()
                    .filter(t -> t.getQualifiedName().equals(info.className))
                    .findFirst().orElse(null);
            if (clazz == null)
                continue;

            // 1. 查找字段是否出现在日志中
            for (String field : info.sensitiveFields) {
                List<CtFieldAccess<?>> fieldAccesses = clazz.getElements(new TypeFilter<>(CtFieldAccess.class));
                for (CtFieldAccess<?> access : fieldAccesses) {
                    String fieldName = access.getVariable().getSimpleName();
                    // if (!fieldName.equals(field)) {
                    // System.out.println("field:" + field);
                    // System.out.println("ne:" + fieldName);
                    // continue;
                    // }
                    // System.out.println("eq:" + fieldName);

                    CtInvocation<?> parentLog = findEnclosingLogInvocation(access);
                    if (parentLog != null) {
                        // System.out.println("log:" + parentLog);
                        records.add(createRecord(info.className, getMethodName(parentLog),
                                field, parentLog.toString(), parentLog.getPosition().getLine(), "direct"));
                        continue;
                    }

                    // 间接追踪：字段 -> 局部变量 -> 日志参数
                    CtElement parent = access.getParent();
                    if (parent instanceof CtAssignment) {
                        CtExpression<?> left = ((CtAssignment<?, ?>) parent).getAssigned();
                        if (left instanceof CtVariableWrite) {
                            String varName = ((CtVariableWrite<?>) left).getVariable().getSimpleName();
                            List<CtInvocation<?>> invs = clazz.getElements(new TypeFilter<>(CtInvocation.class));
                            for (CtInvocation<?> inv : invs) {
                                if (isLogMethod(inv)) {
                                    for (CtExpression<?> arg : inv.getArguments()) {
                                        if (arg instanceof CtVariableRead &&
                                                ((CtVariableRead<?>) arg).getVariable().getSimpleName()
                                                        .equals(varName)) {
                                            records.add(createRecord(info.className, getMethodName(inv),
                                                    field, inv.toString(), inv.getPosition().getLine(), "indirect"));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 2. 安全方法内直接打印日志
            for (String methodName : info.securityMethods) {
                List<CtMethod<?>> methods = clazz.getMethods().stream()
                        .filter(m -> m.getSimpleName().equals(methodName))
                        .collect(Collectors.toList());

                for (CtMethod<?> method : methods) {
                    List<CtInvocation<?>> invocations = method.getElements(new TypeFilter<>(CtInvocation.class));
                    for (CtInvocation<?> inv : invocations) {
                        if (isLogMethod(inv)) {
                            records.add(createRecord(info.className, method.getSimpleName(),
                                    methodName, inv.toString(), inv.getPosition().getLine(), "direct"));
                        }
                    }

                    // 3. 方法参数作为日志变量（间接传参）
                    for (CtParameter<?> param : method.getParameters()) {
                        String paramName = param.getSimpleName();
                        List<CtVariableAccess<?>> accesses = method
                                .getElements(new TypeFilter<>(CtVariableAccess.class));
                        for (CtVariableAccess<?> va : accesses) {
                            if (va.getVariable().getSimpleName().equals(paramName)) {
                                CtInvocation<?> log = findEnclosingLogInvocation(va);
                                if (log != null) {
                                    records.add(createRecord(info.className, method.getSimpleName(),
                                            paramName, log.toString(), log.getPosition().getLine(), "param"));
                                }
                            }
                        }
                    }
                }
            }
        }

        writeRecordsToJson(records, outputPath);
        System.out.println("分析完成，输出文件: " + outputPath);
    }

    private static CtInvocation<?> findEnclosingLogInvocation(CtElement element) {
        // 向上查找日志语句
        CtElement current = element;
        while (current != null && !(current instanceof CtInvocation)) {
            current = current.getParent();
        }
        if (current instanceof CtInvocation && isLogMethod((CtInvocation<?>) current)) {
            return (CtInvocation<?>) current;
        }

        // 向下数据流分析（当前变量是否被传入日志语句）
        if (element instanceof CtVariableAccess<?>) {
            String varName = ((CtVariableAccess<?>) element).getVariable().getSimpleName();
            // System.out.println("varname:" + varName);
            CtExecutable<?> method = element.getParent(new TypeFilter<>(CtExecutable.class));
            // System.out.println("method:" + method);
            if (method != null) {
                List<CtInvocation<?>> invocations = method.getElements(new TypeFilter<>(CtInvocation.class));
                for (CtInvocation<?> inv : invocations) {
                    if (isLogMethod(inv)) {
                        for (CtExpression<?> arg : inv.getArguments()) {
                            if (arg instanceof CtVariableRead
                                    && ((CtVariableRead<?>) arg).getVariable().getSimpleName().equals(varName)) {
                                return inv;
                            }
                        }
                    }
                }
            }
        }

        return null;
    }

    private static boolean isLogMethod(CtInvocation<?> invocation) {
        return isLoggingOrPrintInvocation(invocation);
    }

    private static String getMethodName(CtInvocation<?> invocation) {
        CtExecutable<?> enclosing = invocation.getParent(new TypeFilter<>(CtExecutable.class));
        return enclosing != null ? enclosing.getSimpleName() : "<unknown>";
    }

    private static LogUsageRecord createRecord(String className, String methodName,
            String sensitiveElement, String logText, int lineNumber, String traceType) {
        LogUsageRecord rec = new LogUsageRecord();
        rec.className = className;
        rec.methodName = methodName;
        rec.sensitiveElement = sensitiveElement;
        rec.logText = logText;
        rec.lineNumber = lineNumber;
        rec.traceType = traceType;
        return rec;
    }

    private static List<SensitiveClassInfo> loadSensitiveClassInfos(String path) throws IOException {
        try (Reader reader = new FileReader(path)) {
            Gson gson = new Gson();
            SensitiveClassInfo[] array = gson.fromJson(reader, SensitiveClassInfo[].class);
            return Arrays.asList(array);
        }
    }

    private static void writeRecordsToJson(List<LogUsageRecord> records, String outputPath) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(outputPath), "UTF-8")) {
            gson.toJson(records, writer);
        }
    }

}
