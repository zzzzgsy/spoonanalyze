package com.example.analyzer;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.example.detector.SensitiveDetector.LogLocation;
import com.example.detector.SensitiveDetector.SensitiveClassInfo;
import com.example.detector.SensitiveDetector.SensitiveLocalVariable;
import com.example.detector.SensitiveDetector.SensitiveMethodInfo;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import spoon.Launcher;
import spoon.reflect.CtModel;
import spoon.reflect.code.CtExpression;
import spoon.reflect.code.CtInvocation;
import spoon.reflect.code.CtLocalVariable;
import spoon.reflect.code.CtVariableAccess;
import spoon.reflect.code.CtVariableRead;
import spoon.reflect.declaration.CtElement;
import spoon.reflect.declaration.CtExecutable;
import spoon.reflect.declaration.CtField;
import spoon.reflect.declaration.CtMethod;
import spoon.reflect.declaration.CtParameter;
import spoon.reflect.declaration.CtType;
import spoon.reflect.declaration.CtVariable;
import spoon.reflect.reference.CtExecutableReference;
import spoon.reflect.visitor.filter.TypeFilter;

import static com.example.detector.LogDetector.*;
import static com.example.detector.SensitiveDetector.*;

public class Analyzer {
    private static String getSimpleNameFromSource(CtElement source) {
        if (source instanceof CtVariable) {
            return ((CtVariable<?>) source).getSimpleName();
        } else if (source instanceof CtVariableAccess) {
            return ((CtVariableAccess<?>) source).getVariable().getSimpleName();
        } else if (source instanceof CtParameter) {
            return ((CtParameter<?>) source).getSimpleName();
        }
        return source.toString(); // fallback
    }

    // 从变量/方法出发，递归追踪其是否最终进入日志打印
    public static void analyzeDataFlowToLog(CtElement source, CtType<?> containerClass, SensitiveClassInfo info,
            Set<CtElement> visited, String path) {
        // System.out.println("source:" + source);
        if (visited.contains(source))
            return;
        visited.add(source);

        List<CtInvocation<?>> invocations = containerClass.getElements(new TypeFilter<>(CtInvocation.class));
        String targetName = getSimpleNameFromSource(source); // 新增方法提取变量名

        for (CtInvocation<?> inv : invocations) {
            if (isLoggingOrPrintInvocation(inv)) {
                for (CtExpression<?> arg : inv.getArguments()) {
                    if (arg instanceof CtVariableRead) {
                        String argName = ((CtVariableRead<?>) arg).getVariable().getSimpleName();
                        if (argName.equals(targetName)) {
                            info.logLocations.add(new LogLocation(
                                    containerClass.getQualifiedName(),
                                    inv.getParent(CtMethod.class) != null
                                            ? inv.getParent(CtMethod.class).getSimpleName()
                                            : "unknown",
                                    inv.getPosition() != null ? inv.getPosition().getLine() : -1));
                            info.dataFlowPath.add(path + " -> " + inv.toString());
                            return;
                        }
                    }
                }
            }

            // 可选：跨类追踪逻辑保留不变

            // 【2】递归调用分析（跨方法/跨类）
            CtExecutableReference<?> execRef = inv.getExecutable();
            if (execRef != null && execRef.getDeclaration() != null) {
                CtExecutable<?> callee = execRef.getDeclaration();
                if (callee instanceof CtMethod) {
                    CtMethod<?> method = (CtMethod<?>) callee;

                    // 【2.1】判断 source 是否作为实参传入
                    List<CtExpression<?>> actualArgs = inv.getArguments();
                    List<CtParameter<?>> params = method.getParameters();
                    for (int i = 0; i < Math.min(actualArgs.size(), params.size()); i++) {
                        CtExpression<?> actual = actualArgs.get(i);
                        CtParameter<?> formal = params.get(i);
                        if (actual.toString().contains(source.toString())) {
                            analyzeDataFlowToLog(
                                    formal,
                                    method.getParent(CtType.class),
                                    info,
                                    visited,
                                    path + " -> " + method.getSimpleName() + "(" + formal.getSimpleName() + ")");
                        }
                    }

                    // 如果没参数匹配，也可以直接追踪 method 体（假设 source 是 this.属性 或隐含变量）
                    analyzeDataFlowToLog(method, method.getParent(CtType.class), info, visited,
                            path + " -> " + method.getSimpleName());
                }
            }
        }
    }

    // ---------------------- 总体模型分析 ----------------------
    public static List<SensitiveClassInfo> analyzeModel(CtModel model) {
        List<SensitiveClassInfo> result = new ArrayList<>();

        for (CtType<?> type : model.getAllTypes()) {
            SensitiveClassInfo info = new SensitiveClassInfo();
            info.className = type.getQualifiedName();

            // ① 检测安全相关方法（名称 / 参数 / 返回类型 / 注解）
            for (CtMethod<?> method : type.getMethods()) {
                if (isSecurityRelatedMethod(method) || containsSensitiveSQL(method)) {
                    // 创建SensitiveMethodInfo对象
                    SensitiveMethodInfo methodInfo = new SensitiveMethodInfo();
                    methodInfo.methodName = method.getSimpleName();

                    // 数据流分析
                    analyzeDataFlowToLog(method, type, info, new HashSet<>(), method.getSimpleName());

                    // 添加到列表
                    info.securityMethods.add(methodInfo); // 现在添加的是对象而非字符串
                }
            }

            // ② 检测类级别敏感字段（替换 stream 写法为传统写法）
            for (CtField<?> field : type.getFields()) {
                if (isSensitiveField(field)) {
                    System.out.println("field:" + field);
                    // 预留位置：可以在这里扩展更多字段逻辑
                    info.sensitiveFields.add(field.getSimpleName());
                    analyzeDataFlowToLog(field, type, info, new HashSet<>(), field.getSimpleName());
                }
            }

            // ③ 检测方法体中的敏感局部变量
            for (CtMethod<?> method : type.getMethods()) {
                List<CtLocalVariable<?>> locals = method.getElements(new TypeFilter<>(CtLocalVariable.class));
                for (CtLocalVariable<?> local : locals) {
                    if (isSensitiveVariable(local)) {
                        System.out.println("local:" + local);
                        // 可在此处扩展：分析赋值来源、使用位置等
                        info.sensitiveLocals.add(new SensitiveLocalVariable(
                                local.getSimpleName(),
                                method.getSimpleName(),
                                local.getPosition().getLine()));
                        analyzeDataFlowToLog(local, type, info, new HashSet<>(), local.getSimpleName());

                    }
                }
            }

            if (!info.sensitiveFields.isEmpty() || !info.sensitiveLocals.isEmpty()) {
                result.add(info);
            }
        }
        return result;
    }

    // ---------------------- 输出为 JSON ----------------------
    public static void writeToJson(List<SensitiveClassInfo> data, String outputPath) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(outputPath), "UTF-8")) {
            gson.toJson(data, writer);
        }
    }

    public static void main(String[] args) throws IOException {
        String sourcePath = "C:\\dataset\\SpingBoot\\springboot018_muying-master\\springboot018_muying-master\\muyingshangcheng\\src\\main\\java";
        String outputPath = "C:\\dataset\\spoonanalyze\\output\\out4.json";

        Launcher launcher = new Launcher();
        launcher.addInputResource(sourcePath);
        launcher.getEnvironment().setNoClasspath(true);
        CtModel model = launcher.buildModel();

        List<SensitiveClassInfo> detected = analyzeModel(model);
        writeToJson(detected, outputPath);

        System.out.println("分析完成，已保存至: " + outputPath);
    }

}
