package com.example.util;

import spoon.reflect.code.CtStatement;
import spoon.reflect.declaration.CtMethod;

import static com.example.detector.SensitiveDetector.*;

import java.util.Set;
import java.util.concurrent.*;

import com.example.EnhancedDependencyAnalyzer;

public class AnalysisCache {
    private static final ConcurrentMap<String, Set<String>> dataFlowCache = new ConcurrentHashMap<>();
    private static final ConcurrentMap<String, Boolean> securityMethodCache = new ConcurrentHashMap<>();

    // 带缓存的数据流分析
    public Set<String> cachedDataFlowAnalysis(CtMethod<?> method, CtStatement stmt) {
        String key = method.getSignature() + ":" + stmt.getPosition().getLine();
        return dataFlowCache.computeIfAbsent(key,
                k -> EnhancedDependencyAnalyzer.enhancedExtractVariables(method, stmt));
    }

    // 带缓存的安全方法检测
    public boolean isSecurityMethodCached(CtMethod<?> method) {
        String key = method.getSignature();
        return securityMethodCache.computeIfAbsent(key, k -> isSecurityRelatedMethod(method));
    }

    // 定期清理缓存
    public static void clearCache() {
        dataFlowCache.clear();
        securityMethodCache.clear();
    }
}