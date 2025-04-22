package com.example.detector;

import com.example.detector.SensitiveDetector.SensitiveMethodInfo;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import spoon.Launcher;
import spoon.reflect.CtModel;
import spoon.reflect.code.CtAssignment;
import spoon.reflect.code.CtInvocation;
import spoon.reflect.code.CtLocalVariable;
import spoon.reflect.declaration.*;
import spoon.reflect.visitor.filter.TypeFilter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.*;
import java.util.regex.Pattern;

public class SensitiveDetector {
    // 信息

    // ====================== 统一数据结构 ======================
    public static class SensitiveClassInfo {
        public String className;
        public List<String> sensitiveFields = new ArrayList<>();
        // public List<String> securityMethods = new ArrayList<>();
        public List<SensitiveMethodInfo> securityMethods = new ArrayList<>();
        // 方法内的敏感局部变量（需记录所属方法）
        public List<SensitiveLocalVariable> sensitiveLocals = new ArrayList<>();
        public List<String> dataFlowPath = new ArrayList<>();
        public List<LogLocation> logLocations = new ArrayList<>();
        public List<String> unsafeInitializations = new ArrayList<>();

    }

    // public class SensitiveField {
    // String fieldName;
    // List<DataFlowNode> dataFlows = new ArrayList<>(); // 数据流路径
    // List<LogLocation> logExposures = new ArrayList<>(); // 日志暴露点
    // }

    // public class SensitiveMethod {
    // String methodName;
    // List<SensitiveOperation> operations = new ArrayList<>(); // 敏感操作
    // List<LogLocation> logExposures = new ArrayList<>();
    // }

    // 新增内部类存储更丰富的信息
    public static class SensitiveMethodInfo {
        public String methodName;
        // public List<String> issues = new ArrayList<>();
    }

    public static class SensitiveLocalVariable {
        String variableName;
        String methodName;
        int lineNumber;

        // 添加构造函数
        public SensitiveLocalVariable(String variableName, String methodName, int lineNumber) {
            this.variableName = variableName;
            this.methodName = methodName;
            this.lineNumber = lineNumber;
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

    public class DataFlowNode {
        String variableName;
        String operation; // 如 "ASSIGNMENT", "METHOD_CALL"
        String codeSnippet;
        int lineNumber;
    }

    public static class LogLocation {
        // String className;
        String methodName;
        int line;

        public LogLocation(String className, String methodName, int line) {
            // this.className = className;
            this.methodName = methodName;
            this.line = line;
        }
    }

    // public class SensitiveOperation {
    // String operationType; // 如 "GET_ATTRIBUTE"
    // String codeSnippet; // 代码片段
    // int lineNumber;
    // }

    // 注释
    public static final List<Pattern> SECURITY_ANNOTATION_PATTERNS = Arrays.asList(
            Pattern.compile("(?i).*(Sensitive|Encrypted|PII|Confidential|Secret|Security|Auth).*"),
            Pattern.compile("(?i).*(Password|Token|Key|Credential|Permission|Role|Privilege).*"));

    public static boolean hasSecurityAnnotation(CtElement element) {
        return element.getAnnotations().stream()
                .anyMatch(anno -> SECURITY_ANNOTATION_PATTERNS.stream()
                        .anyMatch(pattern -> pattern.matcher(anno.getAnnotationType().getSimpleName()).matches()));
    }

    // 数据库操作
    public static final List<Pattern> SQL_SENSITIVE_PATTERNS = Arrays.asList(
            Pattern.compile("(?i).*(select|insert|update|delete|merge|truncate|drop|alter|create).*"),
            Pattern.compile("(?i).*(where|from|join|union|groupby|orderby|having|limit|offset).*"));

    public static boolean containsSensitiveSQL(CtMethod<?> method) {
        return method.getElements(e -> e instanceof CtInvocation<?>)
                .stream()
                .anyMatch(inv -> {
                    String invocationStr = inv.toString().toLowerCase();
                    return SQL_SENSITIVE_PATTERNS.stream()
                            .anyMatch(p -> p.matcher(invocationStr).matches()) &&
                            invocationStr.matches(".*(password|token|secret|auth).*");
                });
    }

    // 敏感变量名
    public static final List<Pattern> SENSITIVE_FIELD_PATTERNS = Arrays.asList(
            Pattern.compile("(?i).*(password|pwd|pass(wd|word|phrase)|secret|token|auth|apikey|idcard|identity).*",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i).*(username|account|userId|yonghu|id|realname|name|ry|xm|mc|auth).*",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i).*(email|phone|mobile|telephone|code).*",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i).*(key|privatekey|publickey|certificate|signature|digest|hash|salt|iv|nonce).*",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i).*(session|cookie|jwt|oauth|saml|openid|jwe).*",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i).*(address|location|gps|coordinate|latitude|longitude|geo).*",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i).*(file|photo|pic|img|path|upload|download).*",
                    Pattern.CASE_INSENSITIVE));
    // 敏感方法名
    public static final List<Pattern> SECURITY_METHOD_PATTERNS = Arrays.asList(
            Pattern.compile("(?i).*(login|logout|auth|authenticate|verify|validate|check|verify).*"),
            Pattern.compile("(?i).*(access|permission|role|privilege|authorize|securityCheck|policy|acl).*"),
            Pattern.compile("(?i).*(encrypt|decrypt|sign|verifySignature|hash|hmac|digest|encode|decode).*"),
            Pattern.compile("(?i).*(filter|interceptor|guard|protect|sanitize|escape|inject).*"),
            Pattern.compile("(?i).*(session|cookie|token|jwt|oauth|saml|openid|sso).*"),
            Pattern.compile("(?i).*(audit|log|track|trace|monitor|detect|alert).*"));

    // ---------------------- 方法中检测敏感变量 ----------------------
    public static boolean isSensitiveVariable(CtLocalVariable<?> local) {
        String varName = local.getSimpleName();
        // ① 通过变量名判断是否敏感（如 username、password 等）
        return SENSITIVE_FIELD_PATTERNS.stream().anyMatch(p -> p.matcher(varName).matches());
    }

    public static void analyzeMethodLocals(CtMethod<?> method, SensitiveClassInfo info) {
        List<CtLocalVariable<?>> locals = method.getElements(new TypeFilter<>(CtLocalVariable.class));
        for (CtLocalVariable<?> local : locals) {
            if (isSensitiveVariable(local)) {
                // 可在此处扩展：分析赋值来源、使用位置等
                info.sensitiveLocals.add(new SensitiveLocalVariable(
                        local.getSimpleName(),
                        method.getSimpleName(),
                        local.getPosition().getLine()));
            }
        }
    }

    // ---------------------- 类中检测敏感字段 ----------------------
    public static boolean isSensitiveField(CtField<?> field) {
        String name = field.getSimpleName();
        return SENSITIVE_FIELD_PATTERNS.stream().anyMatch(p -> p.matcher(name).matches());
    }

    // ---------------------- 类中检测安全相关方法 ----------------------
    public static boolean isSecurityRelatedMethod(CtMethod<?> method) {
        String name = method.getSimpleName();

        // ① 方法名包含敏感关键词（如 login、auth、access）
        boolean nameMatch = SECURITY_METHOD_PATTERNS.stream()
                .anyMatch(p -> p.matcher(name).matches());

        // ② 方法参数名是否包含敏感关键词（如 password）
        boolean paramMatch = method.getParameters().stream()
                .anyMatch(p -> SENSITIVE_FIELD_PATTERNS.stream()
                        .anyMatch(pattern -> pattern.matcher(p.getSimpleName()).matches()));

        // ③ 返回类型是否敏感（如 Token、String）
        boolean returnMatch = method.getType() != null && !method.getType().getSimpleName().equals("void") &&
                SENSITIVE_FIELD_PATTERNS.stream()
                        .anyMatch(p -> p.matcher(method.getType().getSimpleName()).matches());

        // ④ 注解是否包含安全关键词（如 @Secured）
        boolean annotationMatch = hasSecurityAnnotation(method);

        // 新增语义分析检查
        boolean semanticCheck = method.getElements(e -> true).stream()
                .anyMatch(e -> {
                    if (e instanceof CtAssignment) {
                        return SemanticAnalyzer.isUnencryptedSensitiveAssignment((CtAssignment<?, ?>) e);
                    } else if (e instanceof CtInvocation) {
                        CtInvocation<?> inv = (CtInvocation<?>) e;
                        return SemanticAnalyzer.isInsecureRandomUsage(inv) ||
                                SemanticAnalyzer.isSensitiveSqlConcatenation(inv);
                    }
                    return false;
                });

        return nameMatch || paramMatch || returnMatch || annotationMatch || semanticCheck;
    }

    public static List<SensitiveClassInfo> analyzeModel(CtModel model) {
        List<SensitiveClassInfo> result = new ArrayList<>();

        for (CtType<?> type : model.getAllTypes()) {
            SensitiveClassInfo info = new SensitiveClassInfo();
            info.className = type.getQualifiedName();

            // ① 检测安全相关方法（名称 / 参数 / 返回类型 / 注解）
            for (CtMethod<?> method : type.getMethods()) {
                if (isSecurityRelatedMethod(method) || containsSensitiveSQL(method)) {

                    // info.securityMethods.add(method.getSimpleName());

                    SensitiveMethodInfo methodInfo = new SensitiveMethodInfo();
                    methodInfo.methodName = method.getSimpleName();
                    // for (CtAssignment<?, ?> assign : method.getElements(new
                    // TypeFilter<>(CtAssignment.class))) {
                    // if (SemanticAnalyzer.isUnencryptedSensitiveAssignment(assign)) {
                    // methodInfo.issues.add("Unencrypted assignment at line: " +
                    // assign.getPosition().getLine());
                    // }
                    // }
                    info.securityMethods.add(methodInfo);
                }
            }

            // ② 检测类级别敏感字段（替换 stream 写法为传统写法）
            for (

            CtField<?> field : type.getFields()) {
                if (isSensitiveField(field)) {
                    // 预留位置：可以在这里扩展更多字段逻辑
                    info.sensitiveFields.add(field.getSimpleName());
                    // 检查字段初始化是否安全
                    if (field.getDefaultExpression() != null &&
                            !SemanticAnalyzer.isEncryptedOperation(field.getDefaultExpression())) {
                        info.unsafeInitializations.add(field.getSimpleName());
                    }
                }
            }

            // ③ 检测方法体中的敏感局部变量
            for (CtMethod<?> method : type.getMethods()) {
                List<CtLocalVariable<?>> locals = method.getElements(new TypeFilter<>(CtLocalVariable.class));
                for (CtLocalVariable<?> local : locals) {
                    if (isSensitiveVariable(local)) {
                        // 可在此处扩展：分析赋值来源、使用位置等
                        info.sensitiveLocals.add(new SensitiveLocalVariable(
                                local.getSimpleName(),
                                method.getSimpleName(),
                                local.getPosition().getLine()));

                        // 检查字段初始化是否安全
                        if (local.getDefaultExpression() != null &&
                                !SemanticAnalyzer.isEncryptedOperation(local.getDefaultExpression())) {
                            info.unsafeInitializations.add(local.getSimpleName());
                        }

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

    // ---------------------- 主程序入口 ----------------------
    public static void main(String[] args) throws IOException {
        String sourcePath = "C:\\dataset\\SpingBoot\\springboot018_muying-master\\springboot018_muying-master\\muyingshangcheng\\src\\main\\java";
        String outputPath = "C:\\dataset\\spoonanalyze\\output\\out3.json";

        Launcher launcher = new Launcher();
        launcher.addInputResource(sourcePath);
        launcher.getEnvironment().setNoClasspath(true);
        CtModel model = launcher.buildModel();

        List<SensitiveClassInfo> detected = analyzeModel(model);
        writeToJson(detected, outputPath);

        System.out.println("分析完成，已保存至: " + outputPath);
    }

}
