package com.example.util;

import com.example.analyzer.EnhancedAnalyzer.FieldUsage;
import com.example.analyzer.EnhancedAnalyzer.SensitiveClassInfo;
import com.google.gson.*;
import java.io.*;
import java.lang.reflect.Type;
import java.util.*;
import java.util.Map.Entry;

public class JsonUtils {

    public static void writeToJson(List<SensitiveClassInfo> data, String outputPath) throws IOException {
        Gson gson = new GsonBuilder()
                .setPrettyPrinting()
                .disableHtmlEscaping()
                .registerTypeAdapter(SensitiveClassInfo.class, new SensitiveClassInfoSerializer())
                .create();

        try (Writer writer = new OutputStreamWriter(new FileOutputStream(outputPath), "UTF-8")) {
            gson.toJson(data, writer);
        }
    }

    // 自定义序列化器
    static class SensitiveClassInfoSerializer implements JsonSerializer<SensitiveClassInfo> {
        @Override
        public JsonElement serialize(SensitiveClassInfo src, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject obj = new JsonObject();

            if (src.className != null && !src.className.isEmpty()) {
                obj.addProperty("className", src.className);
            }
            if (src.securityMethods != null && !src.securityMethods.isEmpty()) {
                obj.add("securityMethods", context.serialize(src.securityMethods));
            }
            if (src.sensitiveFields != null && !src.sensitiveFields.isEmpty()) {
                obj.add("sensitiveFields", context.serialize(src.sensitiveFields));
            }
            if (src.sensitiveLocals != null && !src.sensitiveLocals.isEmpty()) {
                obj.add("sensitiveLocals", context.serialize(src.sensitiveLocals));
            }
            // if (src.unsafeInitializations != null &&
            // !src.unsafeInitializations.isEmpty()) {
            // obj.add("unsafeInitializations",
            // context.serialize(src.unsafeInitializations));
            // }
            // if (src.logLocations != null && !src.logLocations.isEmpty()) {
            // obj.add("logLocations", context.serialize(src.logLocations));
            // }
            // if (src.dataFlowPath != null && !src.dataFlowPath.isEmpty()) {
            // obj.add("dataFlowPath", context.serialize(src.dataFlowPath));
            // }

            if (src.flowRecords != null && !src.flowRecords.isEmpty()) {
                obj.add("flowRecords", context.serialize(src.flowRecords));
            }
            // if (src.dotGraph != null && !src.dotGraph.isEmpty()) {
            // obj.add("dotGraph", context.serialize(src.dotGraph));
            // }
            if (src.fieldUsages != null && !src.fieldUsages.isEmpty()) {
                // 只序列化非空 fieldUsages
                JsonObject fieldUsagesObj = new JsonObject();
                for (Entry<String, Set<FieldUsage>> entry : src.fieldUsages.entrySet()) {
                    if (entry.getValue() != null && !entry.getValue().isEmpty()) {
                        fieldUsagesObj.add(entry.getKey(), context.serialize(entry.getValue()));
                    }
                }
                if (fieldUsagesObj.size() > 0) {
                    obj.add("fieldUsages", fieldUsagesObj);
                }
            }

            return obj;
        }
    }
}
