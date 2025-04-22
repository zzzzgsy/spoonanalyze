package com.example.enhancement;

import com.example.util.AnalysisCache;
import com.google.gson.*;
import spoon.Launcher;
import spoon.reflect.CtModel;
import spoon.reflect.code.*;
import spoon.reflect.declaration.*;
import spoon.reflect.visitor.filter.TypeFilter;

import static com.example.detector.LogDetector.isLoggingOrPrintInvocation;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.*;

public class LogEnhancement {
    // 初始化缓存
    private static final AnalysisCache analysisCache = new AnalysisCache();

    // 报告记录结构
    static class LogCheckResult {
        String className;
        String methodName;
        int lineNumber;
        String failPathCode;
        boolean hasLog;
        List<String> logArgs = new ArrayList<>();
        List<String> missingElements = new ArrayList<>();
        String suggestion;
    }

    public static void main(String[] args) throws Exception {
        String sourcePath = "C:\\dataset\\SpingBoot\\springboot018_muying-master\\springboot018_muying-master\\muyingshangcheng\\src\\main\\java";
        String outputPath = "C:\\dataset\\spoonanalyze\\output\\security-log-report2.json";

        Launcher launcher = new Launcher();
        launcher.addInputResource(sourcePath);
        launcher.getEnvironment().setNoClasspath(true);
        CtModel model = launcher.buildModel();

        List<LogCheckResult> report = new ArrayList<>();

        for (CtType<?> type : model.getAllTypes()) {
            for (CtMethod<?> method : type.getMethods()) {
                // if (isSecurityRelatedMethod(method)) {
                if (analysisCache.isSecurityMethodCached(method)) { // 使用缓存判断
                    List<CtStatement> failPaths = detectFailPaths(method);
                    for (CtStatement stmt : failPaths) {
                        LogCheckResult result = new LogCheckResult();
                        result.className = type.getQualifiedName();
                        result.methodName = method.getSimpleName();
                        result.lineNumber = stmt.getPosition().getLine();
                        result.failPathCode = stmt.toString();

                        CtInvocation<?> log = findNearbyLog(stmt);
                        if (log != null) {
                            result.hasLog = true;
                            result.logArgs = extractLogArguments(log);
                            result.missingElements = checkMissingLogElements(result.logArgs);
                        } else {
                            result.hasLog = false;
                            // Set<String> sliceVars = extractVariablesBySlice(method, stmt);
                            Set<String> sliceVars = analysisCache.cachedDataFlowAnalysis(method, stmt);
                            result.suggestion = generateLogTemplate(method, sliceVars);
                        }
                        report.add(result);
                    }
                }
            }
        }

        writeToJson(report, outputPath);
        System.out.println("日志分析完成，结果已保存至: " + outputPath);
    }

    public static Set<String> extractVariablesBySlice(CtMethod<?> method, CtStatement failStmt) {
        Set<String> result = new HashSet<>();

        // 1. 收集方法参数作为初始 subject 候选
        for (CtParameter<?> p : method.getParameters()) {
            result.add(p.getSimpleName());
        }

        // 2. 后向切片收集数据依赖的变量（带 visited 防止无限递归）
        Set<Integer> visitedIds = new HashSet<>();
        collectDataDependentVariables(failStmt, result, visitedIds);

        // 3. 收集控制依赖的条件变量（如果你实现了这个）
        collectControlDependentVariables(failStmt, result);

        return result;
    }

    private static void collectDataDependentVariables(CtElement element, Set<String> variables,
            Set<Integer> visitedIds) {
        if (element == null)
            return;

        int id = System.identityHashCode(element);
        if (visitedIds.contains(id))
            return;
        visitedIds.add(id);

        try {
            List<CtVariableAccess<?>> accesses = element.getElements(new TypeFilter<>(CtVariableAccess.class));
            for (CtVariableAccess<?> access : accesses) {
                if (access.getVariable() != null) {
                    variables.add(access.getVariable().getSimpleName());
                }
            }
        } catch (Exception e) {
            return;
        }

        // 向上追踪
        collectDataDependentVariables(element.getParent(), variables, visitedIds);
    }

    private static void collectControlDependentVariables(CtStatement stmt, Set<String> variables) {
        CtElement parent = stmt.getParent();
        if (parent instanceof CtIf) {
            CtIf ifStmt = (CtIf) parent;
            ifStmt.getCondition()
                    .getElements(new TypeFilter<>(CtVariableAccess.class))
                    .forEach(va -> variables.add(va.getVariable().getSimpleName()));
        } else if (parent instanceof CtWhile) {
            CtWhile whileStmt = (CtWhile) parent;
            whileStmt.getLoopingExpression()
                    .getElements(new TypeFilter<>(CtVariableAccess.class))
                    .forEach(va -> variables.add(va.getVariable().getSimpleName()));
        } else if (parent instanceof CtFor) {
            CtFor forStmt = (CtFor) parent;
            if (forStmt.getExpression() != null) {
                forStmt.getExpression()
                        .getElements(new TypeFilter<>(CtVariableAccess.class))
                        .forEach(va -> variables.add(va.getVariable().getSimpleName()));
            }
        } else if (parent instanceof CtDo) {
            CtDo doStmt = (CtDo) parent;
            doStmt.getLoopingExpression()
                    .getElements(new TypeFilter<>(CtVariableAccess.class))
                    .forEach(va -> variables.add(va.getVariable().getSimpleName()));
        }
    }

    private static List<CtStatement> detectFailPaths(CtMethod<?> method) {
        List<CtStatement> failPaths = new ArrayList<>();

        // 1. 检测显式的访问控制检查失败
        method.getElements(new TypeFilter<CtIf>(CtIf.class)).forEach(ifStmt -> {
            if (isAccessControlCheck(ifStmt.getCondition())) {
                ifStmt.getThenStatement().getElements(new TypeFilter<CtStatement>(CtStatement.class))
                        .forEach(failPaths::add);
            }
        });

        // 2. 检测返回false/null的路径
        method.getElements(new TypeFilter<CtReturn<?>>(CtReturn.class)).forEach(ret -> {
            if (ret.getReturnedExpression() != null) {
                String val = ret.getReturnedExpression().toString();
                if (val.equalsIgnoreCase("null") || val.equalsIgnoreCase("false")
                        || val.contains("error") || val.contains("deny") || val.contains("reject")) {
                    failPaths.add(ret);
                }
            }
        });

        // 3. 检测抛出异常的路径
        failPaths.addAll(method.getElements(new TypeFilter<CtThrow>(CtThrow.class)));

        return failPaths;
    }

    private static boolean isAccessControlCheck(CtExpression<?> expr) {
        String exprStr = expr.toString();
        return exprStr.contains("checkPermission") || exprStr.contains("hasRole")
                || exprStr.contains("isAllowed") || exprStr.contains("authenticate")
                || exprStr.contains("authorize") || exprStr.contains("validate");
    }

    private static String generateLogTemplate(CtMethod<?> method, Set<String> sliceVars) {
        String action = identifyAction(method);
        String subject = identifySubject(method, sliceVars);
        String object = identifyObject(method, sliceVars);
        String prefix = guessLogPrefix(method, action, object);

        return String.format("log.warn(\"%s - Subject: {}, Action: {}, Object: {}\", %s, %s, %s);",
                prefix, subject, action, object);
    }

    private static String guessLogPrefix(CtMethod<?> method, String action, String object) {
        String methodName = method.getSimpleName().toLowerCase();
        if (methodName.contains("login") || methodName.contains("signin"))
            return "[SEC] 登录失败";
        if (methodName.contains("register") || methodName.contains("signup"))
            return "[SEC] 注册失败";
        if (methodName.contains("auth") || methodName.contains("validate") || methodName.contains("permission"))
            return "[SEC] 权限校验失败";
        if (action.equals("read") || action.equals("write"))
            return "[SEC] 数据操作失败";
        return "[SEC] 操作失败";
    }

    private static String identifySubject(CtMethod<?> method, Set<String> vars) {
        // 1. 查找方法参数中的用户/主体信息
        String subject = method.getParameters().stream()
                .filter(p -> p.getSimpleName().toLowerCase().contains("user")
                        || p.getSimpleName().toLowerCase().contains("principal")
                        || p.getSimpleName().toLowerCase().contains("token"))
                .map(CtNamedElement::getSimpleName)
                .findFirst()
                .orElse(null);

        // 2. 查找变量中的用户/主体信息
        if (subject == null) {
            subject = vars.stream()
                    .filter(v -> v.toLowerCase().contains("user")
                            || v.toLowerCase().contains("principal")
                            || v.toLowerCase().contains("token"))
                    .findFirst()
                    .orElse("unknown");
        }

        return subject;
    }

    private static String identifyAction(CtMethod<?> method) {
        // 从方法名识别操作类型
        String methodName = method.getSimpleName().toLowerCase();
        if (methodName.contains("get") || methodName.contains("read")) {
            return "read";
        } else if (methodName.contains("set") || methodName.contains("write")) {
            return "write";
        } else if (methodName.contains("delete")) {
            return "delete";
        } else if (methodName.contains("create")) {
            return "create";
        } else if (methodName.contains("execute")) {
            return "execute";
        }
        return method.getSimpleName();
    }

    private static String identifyObject(CtMethod<?> method, Set<String> vars) {
        // 1. 查找方法参数中的资源信息
        String object = method.getParameters().stream()
                .filter(p -> p.getSimpleName().toLowerCase().contains("resource")
                        || p.getSimpleName().toLowerCase().contains("file")
                        || p.getSimpleName().toLowerCase().contains("uri")
                        || p.getSimpleName().toLowerCase().contains("url"))
                .map(CtNamedElement::getSimpleName)
                .findFirst()
                .orElse(null);

        // 2. 查找变量中的资源信息
        if (object == null) {
            object = vars.stream()
                    .filter(v -> v.toLowerCase().contains("resource")
                            || v.toLowerCase().contains("file")
                            || v.toLowerCase().contains("uri")
                            || v.toLowerCase().contains("url"))
                    .findFirst()
                    .orElse("unknown");
        }

        return object;
    }

    private static CtInvocation<?> findNearbyLog(CtStatement stmt) {
        CtBlock<?> block = stmt.getParent(new TypeFilter<>(CtBlock.class));
        if (block == null)
            return null;

        List<CtStatement> siblings = block.getStatements();
        int index = siblings.indexOf(stmt);

        for (int i = Math.max(0, index - 2); i < index; i++) {
            CtStatement prev = siblings.get(i);
            if (prev instanceof CtInvocation && isLogMethod((CtInvocation<?>) prev)) {
                return (CtInvocation<?>) prev;
            }
        }
        return null;
    }

    // 判断是否是日志调用
    private static boolean isLogMethod(CtInvocation<?> invocation) {
        return isLoggingOrPrintInvocation(invocation);
    }

    private static List<String> extractLogArguments(CtInvocation<?> log) {
        List<String> args = new ArrayList<>();
        for (CtExpression<?> arg : log.getArguments()) {
            args.add(arg.toString());
        }
        return args;
    }

    private static List<String> checkMissingLogElements(List<String> args) {
        List<String> missing = new ArrayList<>();
        boolean hasSubject = args.stream()
                .anyMatch(s -> s.toLowerCase().contains("user") || s.toLowerCase().contains("token"));
        boolean hasAction = args.stream().anyMatch(s -> s.toLowerCase().contains("login")
                || s.toLowerCase().contains("access") || s.toLowerCase().contains("auth"));
        boolean hasObject = args.stream().anyMatch(s -> s.toLowerCase().contains("uri")
                || s.toLowerCase().contains("resource") || s.toLowerCase().contains("request"));

        if (!hasSubject)
            missing.add("subject");
        if (!hasAction)
            missing.add("action");
        if (!hasObject)
            missing.add("object");
        return missing;
    }

    // ---------------------- 输出为 JSON ----------------------
    public static void writeToJson(List<LogCheckResult> data, String outputPath) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (Writer writer = new OutputStreamWriter(new FileOutputStream(outputPath), "UTF-8")) {
            gson.toJson(data, writer);
        }
    }

}
