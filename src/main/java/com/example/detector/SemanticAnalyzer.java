package com.example.detector;

import spoon.reflect.code.*;
import spoon.reflect.declaration.*;
import spoon.reflect.reference.*;
import spoon.support.sniper.SniperJavaPrettyPrinter;

public class SemanticAnalyzer {

    // 检测未加密的敏感数据赋值
    public static boolean isUnencryptedSensitiveAssignment(CtAssignment<?, ?> assignment) {
        CtExpression<?> assigned = assignment.getAssigned();
        CtExpression<?> value = assignment.getAssignment();

        // 检查被赋值的变量是否是敏感字段
        if (assigned instanceof CtVariableWrite) {
            String varName = ((CtVariableWrite<?>) assigned).getVariable().getSimpleName();
            boolean isSensitive = SensitiveDetector.SENSITIVE_FIELD_PATTERNS.stream()
                    .anyMatch(p -> p.matcher(varName).matches());

            // 如果值是字符串字面量且未加密
            if (isSensitive && value instanceof CtLiteral &&
                    !isEncryptedOperation(value)) {
                return true;
            }
        }
        return false;
    }

    // 检查加密方法调用
    public static boolean isEncryptedOperation(CtExpression<?> expr) {
        return expr.getElements(e -> e instanceof CtInvocation)
                .stream()
                .anyMatch(inv -> {
                    String methodName = ((CtInvocation<?>) inv).getExecutable().getSimpleName();
                    return methodName.matches("(?i)encrypt|encode|hash|digest");
                });
    }

    // 检测不安全的随机数生成
    public static boolean isInsecureRandomUsage(CtInvocation<?> invocation) {
        return invocation.getExecutable().getSimpleName().equals("nextInt") &&
                invocation.getTarget().getType().getQualifiedName().equals("java.util.Random");
    }

    // 检测敏感数据直接拼接SQL
    public static boolean isSensitiveSqlConcatenation(CtInvocation<?> invocation) {
        if (!invocation.getExecutable().getSimpleName().equals("executeQuery")) {
            return false;
        }

        return invocation.getArguments().stream()
                .anyMatch(arg -> {
                    String argStr = arg.toString();
                    return SensitiveDetector.SENSITIVE_FIELD_PATTERNS.stream()
                            .anyMatch(p -> p.matcher(argStr).matches()) &&
                            argStr.contains("+"); // 简单检查字符串拼接
                });
    }
}