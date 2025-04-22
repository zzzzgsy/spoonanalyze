package com.example.detector;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import com.google.re2j.Pattern;

import spoon.Launcher;
import spoon.reflect.CtModel;
import spoon.reflect.code.*;
import spoon.reflect.declaration.CtMethod;
import spoon.reflect.declaration.CtType;
import spoon.reflect.declaration.CtVariable;
import spoon.reflect.reference.CtTypeReference;
import spoon.reflect.reference.CtVariableReference;
import spoon.reflect.visitor.Filter;
import spoon.reflect.visitor.filter.TypeFilter;

public class LogDetector {

    // 标准日志类
    private static final List<String> LOGGER_CLASS_NAMES = Arrays.asList(
            "org.slf4j.Logger",
            "org.apache.log4j.Logger",
            "org.apache.logging.log4j.Logger",
            "ch.qos.logback.classic.Logger",
            "java.util.logging.Logger",
            "wiremock.org.slf4j.Logger", "org.apache.commons.logging.Log");

    // 标准 print 类
    private static final List<String> PRINT_CLASS_NAMES = Arrays.asList(
            "java.io.PrintStream", // System.out
            "cn.hutool.core.lang.Console",
            "cn.hutool.core.util.StrUtil",
            "org.apache.commons.io.output.TeeOutputStream",
            "com.google.common.io.ByteStreams");

    // 自定义日志类名模式
    private static final List<Pattern> CUSTOM_LOG_CLASS_PATTERNS = Arrays.asList(
            Pattern.compile(".*(Logger|LogUtil|LogHelper|LogService|LogFactory|logging|Log).*"),
            Pattern.compile(".*Log[^.]*", Pattern.CASE_INSENSITIVE));

    // 自定义 print 类名模式
    private static final List<Pattern> CUSTOM_PRINT_CLASS_PATTERNS = Arrays.asList(
            Pattern.compile(".*(Console|Printer|OutputUtil|PrintHelper|StrUtil).*"));

    // 日志方法检测逻辑
    private static boolean isLoggingMethod(CtInvocation<?> invocation) {
        String methodName = invocation.getExecutable().getSimpleName();
        if (!methodName.matches("(?i)(trace|debug|info|warn|error|fatal|log|printLog|audit)")) {
            return false;
        }

        // 参数类型检查（至少包含一个String类型参数）
        return hasStringArgument(invocation);
    }

    private static boolean hasStringArgument(CtInvocation<?> invocation) {
        return invocation.getArguments().stream()
                .filter(Objects::nonNull)
                .map(CtExpression::getType)
                .filter(Objects::nonNull)
                .anyMatch(typeRef -> "java.lang.String".equals(typeRef.getQualifiedName()));
    }

    private static boolean isPrintMethod(String methodName) {
        return methodName.matches("(?i)(print|println|printf|console|write|printLog)");
    }

    // print 方法名
    private static final List<String> PRINT_METHOD_NAMES = Arrays.asList(
            "print", "printf", "log", "console", "write");

    private static boolean isNullOrEmptyTarget(CtInvocation<?> invocation) {
        return invocation.getTarget() == null || invocation.getTarget().getType() == null;
    }

    // ---------- 判断标准 log ----------

    private static boolean isStandardLogInvocation(CtInvocation<?> invocation) {
        if (isNullOrEmptyTarget(invocation) || !hasStringArgument(invocation))
            return false;

        return LOGGER_CLASS_NAMES.contains(invocation.getTarget().getType().getQualifiedName());
    }

    private static boolean isCustomLogInvocation(CtInvocation<?> invocation) {

        if (isNullOrEmptyTarget(invocation) || !hasStringArgument(invocation))
            return false;
        String qualifiedName = invocation.getTarget().getType().getQualifiedName();
        // System.out.println("qualifiedName" + qualifiedName);
        return CUSTOM_LOG_CLASS_PATTERNS.stream().anyMatch(p -> p.matcher(qualifiedName).matches());
    }

    private static boolean hasExceptionParameter(CtInvocation<?> invocation) {
        if (!hasStringArgument(invocation))
            return false;
        return invocation.getArguments().stream()
                .anyMatch(arg -> arg.getType() != null &&
                        arg.getType().getQualifiedName().equals("java.lang.Throwable"));
    }

    private static boolean hasLogStyleMessage(CtInvocation<?> invocation) {

        return invocation.getArguments().stream()
                .anyMatch(arg -> arg instanceof CtLiteral &&
                        ((CtLiteral<?>) arg).getValue() instanceof String &&
                        ((String) ((CtLiteral<?>) arg).getValue()).matches(".*(\\{}|%).*"))
                || invocation.getArguments().stream()
                        .anyMatch(arg -> arg instanceof CtBinaryOperator &&
                                ((CtBinaryOperator<?>) arg).getKind() == BinaryOperatorKind.PLUS &&
                                arg.getType().getSimpleName().equals("String"));
    }

    // isVariableLogInvocation 方法
    private static boolean isVariableLogInvocation(CtInvocation<?> invocation) {
        if (!hasStringArgument(invocation))
            return false;
        System.out.println("invocation:" + invocation);
        if (invocation.getTarget() instanceof CtVariableAccess) {
            System.out.println("getTarget:" + invocation.getTarget());
            CtVariableReference<?> varRef = ((CtVariableAccess<?>) invocation.getTarget()).getVariable();
            CtTypeReference<?> varType = resolveVariableType(varRef);
            System.out.println("varRef:" + varType);
            System.out.println("varType:" + varType);
            if (varType == null)
                return false;

            // 同时检查标准继承和自定义模式
            if (isSubtypeOfAny(varType, LOGGER_CLASS_NAMES))
                System.out.println("ok1");
            if (CUSTOM_LOG_CLASS_PATTERNS.stream()
                    .anyMatch(p -> p.matcher(varType.getQualifiedName()).matches()))
                System.out.println("ok2");
            return isSubtypeOfAny(varType, LOGGER_CLASS_NAMES) ||
                    CUSTOM_LOG_CLASS_PATTERNS.stream()
                            .anyMatch(p -> p.matcher(varType.getQualifiedName()).matches());
        }

        CtTypeReference<?> targetType = invocation.getTarget() != null ? invocation.getTarget().getType() : null;

        return targetType != null && (isSubtypeOfAny(targetType, LOGGER_CLASS_NAMES) ||
                CUSTOM_LOG_CLASS_PATTERNS.stream()
                        .anyMatch(p -> p.matcher(targetType.getQualifiedName()).matches()));
    }

    private static boolean isLikelyLogInvocation(CtInvocation<?> invocation) {
        return
        // isLoggingMethod(invocation)
        // ||
        // isStandardLogInvocation(invocation)
        // ||
        // isCustomLogInvocation(invocation)
        // ||
        isVariableLogInvocation(invocation);
        // || hasExceptionParameter(invocation) || hasLogStyleMessage(invocation)
        // || isReflectiveLogInvocation(invocation);
        // 处理变量调用（如 logger.info()）
    }

    // 改进的类型检测（处理动态代理）
    private static boolean isProxyLogType(CtTypeReference<?> typeRef) {
        // 检查实现的接口
        return typeRef != null &&
                typeRef.getSuperInterfaces().stream()
                        .anyMatch(i -> LOGGER_CLASS_NAMES.contains(i.getQualifiedName()));
    }

    // 新增：反射调用模式检测
    private static boolean isReflectiveLogInvocation(CtInvocation<?> invocation) {
        // 匹配Method.invoke调用模式
        if (!hasStringArgument(invocation))
            return false;
        if (invocation.getExecutable().getSignature()
                .equals("invoke(java.lang.Object,java.lang.Object[])")) {
            // System.out.println("invocation" + invocation);
            // 检查第一个参数的类型是否是Logger
            List<CtExpression<?>> args = invocation.getArguments();
            if (args.size() >= 1) {
                CtExpression<?> targetArg = args.get(0);
                System.out.println("targetArg" + targetArg);
                if (targetArg.getType() != null &&
                        isSubtypeOfAny(targetArg.getType(), LOGGER_CLASS_NAMES)) {
                    return true;
                }
            }

            // 检查方法名参数（第二个参数的第一个元素）
            if (args.size() >= 2 && args.get(1) instanceof CtNewArray) {
                CtNewArray<?> paramsArray = (CtNewArray<?>) args.get(1);
                if (!paramsArray.getElements().isEmpty()) {
                    CtExpression<?> methodNameExpr = paramsArray.getElements().get(0);
                    if (methodNameExpr instanceof CtLiteral) {
                        Object value = ((CtLiteral<?>) methodNameExpr).getValue();
                        if (value instanceof String) {
                            // && isLoggingMethod((String) value)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    // ---------- 判断标准 print ----------
    private static boolean isStandardPrintInvocation(CtInvocation<?> invocation) {
        if (isNullOrEmptyTarget(invocation))
            return false;

        String methodName = invocation.getExecutable().getSimpleName();
        if (!PRINT_METHOD_NAMES.contains(methodName))
            return false;

        String targetStr = invocation.getTarget().toString();
        if ("System.out".equals(targetStr) || "System.err".equals(targetStr))
            return true;

        CtTypeReference<?> declaringType = invocation.getExecutable().getDeclaringType();
        return declaringType != null && PRINT_CLASS_NAMES.contains(declaringType.getQualifiedName());
    }

    // // 判断是否是自定义封装类的 print
    private static boolean isCustomPrintInvocation(CtInvocation<?> invocation) {
        if (isNullOrEmptyTarget(invocation))
            return false;

        String methodName = invocation.getExecutable().getSimpleName();
        if (!PRINT_METHOD_NAMES.contains(methodName))
            return false;

        CtTypeReference<?> declaringType = invocation.getExecutable().getDeclaringType();
        return declaringType != null &&
                CUSTOM_PRINT_CLASS_PATTERNS.stream()
                        .anyMatch(p -> p.matcher(declaringType.getQualifiedName()).matches());
    }

    private static boolean isDeclaringTypePrintable(CtInvocation<?> invocation) {
        CtTypeReference<?> declaringType = invocation.getExecutable().getDeclaringType();
        return isSubtypeOfAny(declaringType, PRINT_CLASS_NAMES)
                || CUSTOM_PRINT_CLASS_PATTERNS.stream()
                        .anyMatch(p -> p.matcher(declaringType.getQualifiedName()).matches());
    }

    // 变量类型推导
    // private static CtTypeReference<?> resolveVariableType(CtVariableReference<?>
    // varRef) {
    // if (varRef == null)
    // return null;

    // CtVariable<?> declaration = varRef.getDeclaration();
    // if (declaration == null)
    // return varRef.getType();

    // // 处理var类型推断
    // if (declaration.getType() != null &&
    // "var".equals(declaration.getType().getSimpleName())) {
    // if (declaration instanceof CtLocalVariable) {
    // CtLocalVariable<?> localVar = (CtLocalVariable<?>) declaration;
    // CtExpression<?> expr = localVar.getDefaultExpression();

    // // 增强工厂方法处理
    // if (expr instanceof CtInvocation) {
    // CtInvocation<?> factoryCall = (CtInvocation<?>) expr;
    // // 获取方法声明的返回类型
    // CtTypeReference<?> returnType = factoryCall.getExecutable().getType();
    // System.out.println("[DEBUG] Factory method returns: " + returnType);
    // return returnType;
    // }

    // // 处理其他表达式类型
    // return expr != null ? expr.getType() : varRef.getType();
    // }
    // }

    // // 处理常规类型声明
    // return declaration.getType() != null ? declaration.getType() :
    // varRef.getType();
    // }
    private static CtTypeReference<?> resolveVariableType(CtVariableReference<?> varRef) {
        if (varRef == null)
            return null;
        CtVariable<?> varDecl = varRef.getDeclaration();
        if (varDecl == null)
            return null;

        if (varDecl != null) {
            // 处理显式类型声明
            if (varDecl.getType() != null)
                return varDecl.getType();
            // 处理类型推断（如Java10+的var）
            if (varDecl.getDefaultExpression() != null) {
                return varDecl.getDefaultExpression().getType();
            }
            CtExpression<?> expr = varDecl.getDefaultExpression();
            if (expr instanceof CtInvocation) {
                CtInvocation<?> factoryCall = (CtInvocation<?>) expr;
                return factoryCall.getType();
            }
        }
        return varRef.getType();

    }

    /**
     * 判断类型是否是目标类型或其父类/接口
     */
    private static boolean isSubtypeOfAny(CtTypeReference<?> typeRef, List<String> typeNames) {
        if (typeRef == null)
            return false;

        // 完全匹配
        if (typeNames.contains(typeRef.getQualifiedName()))
            return true;

        CtType<?> typeDecl = typeRef.getTypeDeclaration();
        if (typeDecl == null)
            return false;

        // 检查继承和接口
        return typeDecl.getSuperInterfaces().stream().anyMatch(
                superType -> typeNames.contains(superType.getQualifiedName()))
                || (typeDecl.getSuperclass() != null &&
                        typeNames.contains(typeDecl.getSuperclass().getQualifiedName()));
    }

    private static boolean isSystemOutOrErrAccess(CtInvocation<?> invocation) {
        CtExpression<?> target = invocation.getTarget();
        if (target instanceof CtFieldAccess) {
            CtFieldAccess<?> fieldAccess = (CtFieldAccess<?>) target;
            if ("out".equals(fieldAccess.getVariable().getSimpleName()) ||
                    "err".equals(fieldAccess.getVariable().getSimpleName())) {
                if (fieldAccess.getTarget() instanceof CtTypeAccess) {
                    CtTypeAccess<?> typeAccess = (CtTypeAccess<?>) fieldAccess.getTarget();
                    return "java.lang.System".equals(typeAccess.getAccessedType().getQualifiedName());
                }
            }
        }

        String targetStr = target != null ? target.toString() : "";
        return "System.out".equals(targetStr) || "System.err".equals(targetStr);
    }

    private static boolean isEnhancedPrintMethod(CtInvocation<?> invocation) {
        String methodName = invocation.getExecutable().getSimpleName();
        if (!isPrintMethod(methodName)) {
            return false;
        }

        // 直接使用 getParameters()，它已经是 List<CtTypeReference<?>>
        List<CtTypeReference<?>> paramTypes = invocation.getExecutable().getParameters();

        return paramTypes.isEmpty() || paramTypes.stream()
                .anyMatch(t -> t != null && t.getQualifiedName().equals("java.lang.String"));
    }

    private static boolean isLikelyPrintInvocation(CtInvocation<?> invocation) {
        String methodName = invocation.getExecutable().getSimpleName();

        return isPrintMethod(methodName) || isCustomPrintInvocation(invocation) || isStandardPrintInvocation(invocation)
                || isSystemOutOrErrAccess(invocation) || isDeclaringTypePrintable(invocation)
                || hasExceptionParameter(invocation) || isEnhancedPrintMethod(invocation);

    }

    // ---------- 最终统一判断 ----------
    public static boolean isLoggingOrPrintInvocation(CtInvocation<?> invocation) {
        // System.out.println("invocation:" + invocation);
        if (invocation.getTarget() == null)
            return false;
        return isLikelyPrintInvocation(invocation) || isLikelyLogInvocation(invocation);
    }

    // ---------- 外部调用入口 ----------
    public static List<CtInvocation<?>> detectAllLoggingStatements(CtMethod<?> method) {
        // System.out.println("method" + method);
        return method.getElements(new Filter<CtInvocation<?>>() {
            @Override
            public boolean matches(CtInvocation<?> invocation) {

                return isLoggingOrPrintInvocation(invocation);
            }
        });
    }

    public static void main(String[] args) {
        System.out.println("程序启动");
        Launcher launcher = new Launcher();
        // 关闭无类路径，允许解析项目依赖
        launcher.getEnvironment().setNoClasspath(false);
        // 指明 Java 版本以支持 var
        launcher.getEnvironment().setComplianceLevel(11);

        // 把 commons-logging.jar 加到 Spoon 的 classpath
        launcher.getModelBuilder().setSourceClasspath(new String[] {
                "C:\\dataset\\demo\\target\\commons-logging-1.2.jar"
        });

        launcher.addInputResource("C:\\dataset\\demo\\src\\main\\java");

        launcher.setSourceOutputDirectory("C:\\dataset\\spoonanalyze\\output\\log1.json");
        launcher.getEnvironment().setAutoImports(true);
        launcher.getEnvironment().setCommentEnabled(true);
        launcher.getEnvironment().setCopyResources(false);
        CtModel model = launcher.buildModel();
        List<CtMethod<?>> allMethods = model.getElements(new TypeFilter<>(CtMethod.class));
        for (CtMethod<?> method : allMethods) {
            // System.out.println("method:" + method);
            List<CtInvocation<?>> logs = LogDetector.detectAllLoggingStatements(method);
            for (CtInvocation<?> logCall : logs) {
                System.out.println("日志调用：" + logCall);
            }
        }
    }

}
