package com.test;

import spoon.processing.AbstractProcessor;
import spoon.reflect.code.*;
import spoon.reflect.declaration.*;
import spoon.reflect.factory.Factory;
import spoon.reflect.reference.*;
import spoon.reflect.visitor.Filter;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class LogAnalysisProcessor extends AbstractProcessor<CtMethod<?>> {

    // 敏感信息模式检测
    private static final Pattern SENSITIVE_PATTERN = Pattern.compile(
            "(config|password|token|secret|key|credit.?card|ssn|social.?security)",
            Pattern.CASE_INSENSITIVE);
    private static final List<String> ERROR_KEYWORDS = Arrays.asList(
            "exception", "fail", "error", "unauthorized", "forbidden", "denied", "reject");

    // 记录分析结果
    private final Map<String, List<String>> analysisResults = new HashMap<>();

    public Map<String, List<String>> getAnalysisResults() {
        return analysisResults;
    }

    // . **声明 callGraph**
    private final Map<String, List<CtInvocation<?>>> callGraph = new HashMap<>();

    @Override
    public void process(CtMethod<?> method) {
        buildCallGraph(method); // 构建方法调用图
        // System.out.println(callGraph);
        // 1. 查找所有权限检查点
        List<CtStatement> securityChecks = findSecurityChecks(method);
        // System.out.println("1:" + securityChecks);
        // 2. 查找所有日志记录点
        List<CtInvocation<?>> logStatements = findLogStatements(method);
        // System.out.println("2:" + logStatements);
        // 3. 对每个权限检查后的数据流进行分析
        securityChecks.forEach(check -> {
            analyzeDataFlowAfterSecurity(check, logStatements);
        });
        // System.out.println("3:" + logStatements);
        // 4. 检查日志完整性
        logStatements.forEach(log -> {
            System.out.println("log:" + log);
            detectSensitiveInfo(log);
            checkLogCompleteness(log);

        });
    }

    // 构建方法调用图
    private void buildCallGraph(CtMethod<?> method) {
        List<CtInvocation<?>> invocations = method.getElements(el -> el instanceof CtInvocation<?>)
                .stream()
                .map(el -> (CtInvocation<?>) el)
                .collect(Collectors.toList());
        callGraph.put(method.getSignature(), invocations);
        // System.out.println(callGraph);
    }

    // 查找安全检查
    private List<CtStatement> findSecurityChecks(CtMethod<?> method) {
        return method.getElements(new Filter<CtStatement>() {
            @Override
            public boolean matches(CtStatement element) {
                return element.toString().contains("checkPermission") ||
                        element.toString().contains("hasRole") ||
                        element.toString().contains("isAuthenticated");
            }
        });
    }

    // 查找日志语句
    private List<CtInvocation<?>> findLogStatements(CtMethod<?> method) {
        return method.getElements(new Filter<CtInvocation<?>>() {
            @Override
            public boolean matches(CtInvocation<?> element) {

                // System.out.println(element.getExecutable().getSimpleName());
                return element.getExecutable().getSimpleName().matches("info")
                        // && element.toString().contains("log"))
                        ||
                        element.getTarget() != null &&
                                element.toString().contains("log");
            }
        });
    }

    // 在安全检查后分析数据流，并检查是否有日志
    private void analyzeDataFlowAfterSecurity(CtStatement securityCheck,
            List<CtInvocation<?>> logStatements) {
        // 获取权限检查后的所有语句
        List<CtStatement> subsequentStatements = getSubsequentStatements(securityCheck);

        // 分析数据流关系
        subsequentStatements.forEach(statement -> {
            logStatements.forEach(log -> {
                if (isDataFlowConnected(statement, log)) {
                    // recordAnalysisResult(securityCheck, log, "DATA_FLOW");
                    System.out.println("3:" + securityCheck + log.getShortRepresentation());
                    recordAnalysisResult(securityCheck, "DATA_FLOW", "流向日志: " +
                            log.getShortRepresentation());
                }
            });
        });
    }

    private void checkLogCompleteness(CtInvocation<?> logInvocation) {
        boolean hasSubject = false;
        boolean hasObject = false;
        boolean hasAction = false;

        // 只有在日志包含错误相关关键词时才进行补充
        boolean shouldEnhance = false;
        for (CtExpression<?> arg : logInvocation.getArguments()) {
            String argStr = arg.toString().toLowerCase();
            for (String keyword : ERROR_KEYWORDS) {
                if (argStr.contains(keyword)) {
                    shouldEnhance = true;
                    break;
                }
            }
        }

        if (!shouldEnhance) {
            return; // 不处理非错误类日志
        }

        // 检查日志参数是否包含关键要素
        for (CtExpression<?> arg : logInvocation.getArguments()) {
            String argStr = arg.toString();
            if (argStr.contains("user") || argStr.contains("subject")) {
                hasSubject = true;
            }
            if (argStr.contains("resource") || argStr.contains("object")) {
                hasObject = true;
            }
            if (argStr.contains("action") || argStr.contains("operation")) {
                hasAction = true;
            }
        }

        if (!hasSubject || !hasObject || !hasAction) {
            String missing = "";
            if (!hasSubject)
                missing += "subject,";
            if (!hasObject)
                missing += "object,";
            if (!hasAction)
                missing += "action";
            System.out.println("缺少：" + missing);

            recordAnalysisResult(logInvocation, "MISSING_ELEMENTS", missing);

            // 自动补充缺失的日志元素
            augmentLogStatement(logInvocation, missing);
        }
    }

    private void detectSensitiveInfo(CtInvocation<?> logInvocation) {
        List<CtExpression<?>> argumentsCopy = new ArrayList<>(logInvocation.getArguments());

        for (CtExpression<?> arg : argumentsCopy) {
            System.out.println("参数：" + arg);

            // 只处理变量表达式，跳过字符串常量
            if (!(arg instanceof CtLiteral) && SENSITIVE_PATTERN.matcher(arg.toString()).find()) {
                recordAnalysisResult(logInvocation, "SENSITIVE_INFO", arg.toString());

                // 自动添加脱敏处理
                desensitizeLogArgument(logInvocation, arg);
            }
        }
    }

    // 替换敏感信息
    private void desensitizeLogArgument(CtInvocation<?> logInvocation, CtExpression<?> sensitiveArg) {
        // 根据脱敏策略生成代码，这里以掩码为例
        String original = sensitiveArg.toString();

        // 可配置的脱敏方式：mask 或 hash
        String desensitizeMethod = "mask"; // 可替换为 "hash"
        String replacement;
        if (desensitizeMethod.equals("mask")) {
            replacement = original + ".replaceAll(\".\", \"*\")";
        } else {
            replacement = "hashData(" + original + ")";
        }

        System.out.println("替换敏感参数：" + original + " => " + replacement);

        // 替换参数表达式
        CtCodeSnippetExpression<?> replacementExpr = getFactory().createCodeSnippetExpression(replacement);
        System.out.println("replacementExpr:" + replacementExpr);
        sensitiveArg.replace(replacementExpr);
    }

    private void augmentLogStatement(CtInvocation<?> logInvocation, String missingElements) {
        Factory factory = getFactory();

        StringBuilder prefixBuilder = new StringBuilder();
        if (missingElements.contains("subject")) {
            prefixBuilder.append("\"subject: \" + SecurityUtils.getCurrentUser() + \", \" + ");
        }
        if (missingElements.contains("object")) {
            prefixBuilder.append("\"object: \" + this.getClass().getSimpleName() + \", \" + ");
        }
        if (missingElements.contains("action")) {
            prefixBuilder
                    .append("\"action: \" + Thread.currentThread().getStackTrace()[1].getMethodName() + \", \" + ");

        }

        List<CtExpression<?>> args = logInvocation.getArguments();
        if (!args.isEmpty()) {
            CtExpression<?> firstArg = args.get(0);
            String originalMsg = firstArg.toString();

            // 拼接补充信息和原有 message
            String newMessage = prefixBuilder.toString() + originalMsg;

            // 用新的 message 表达式替换旧的第一个参数
            CtCodeSnippetExpression<?> newMessageExpr = factory.Code().createCodeSnippetExpression(newMessage);
            args.set(0, newMessageExpr);
        }
    }

    private boolean isDataFlowConnected(CtStatement source, CtInvocation<?> target) {
        // 获取源语句中定义的所有变量
        Set<CtVariableReference<?>> definedVars = new HashSet<>();
        source.getElements(new Filter<CtAssignment<?, ?>>() {
            @Override
            public boolean matches(CtAssignment<?, ?> assignment) {
                if (assignment.getAssigned() instanceof CtVariableReference) {
                    definedVars.add((CtVariableReference<?>) assignment.getAssigned());
                }
                return false;
            }
        });

        // 检查目标日志是否使用了这些变量
        for (CtVariableReference<?> varRef : target.getElements(new Filter<CtVariableReference<?>>() {
            @Override
            public boolean matches(CtVariableReference<?> variable) {
                return true;
            }
        })) {
            if (definedVars.contains(varRef)) {
                return true;
            }
        }
        return false;
    }

    private void recordAnalysisResult(CtElement element, String type, String details) {
        String key = element.getPosition() + " - " + element.getClass().getSimpleName();
        System.out.println(key);
        analysisResults.computeIfAbsent(key, k -> new ArrayList<>())
                .add(type + ": " + details);
    }

    // 获取安全检查后续的代码
    private List<CtStatement> getSubsequentStatements(CtStatement statement) {
        List<CtStatement> subsequent = new ArrayList<>();
        CtBlock<?> parentBlock = statement.getParent(CtBlock.class);
        if (parentBlock != null) {
            boolean found = false;
            for (CtStatement s : parentBlock.getStatements()) {
                if (found) {
                    subsequent.add(s);
                }
                if (s == statement) {
                    found = true;
                }
            }
        }
        return subsequent;
    }
}