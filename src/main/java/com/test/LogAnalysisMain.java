package com.test;

import spoon.Launcher;
//import spoon.reflect.CtModel;
import spoon.support.sniper.SniperJavaPrettyPrinter;
import java.io.FileWriter;
import com.google.gson.GsonBuilder;

public class LogAnalysisMain {
    public static void main(String[] args) {
        System.out.println("程序启动");
        Launcher launcher = new Launcher();

        // final Factory factory = launcher.getFactory();
        // final ProcessingManager processingManager = new
        // QueueProcessingManager(factory);
        final LogAnalysisProcessor processor = new LogAnalysisProcessor();

        launcher.addProcessor(processor);
        // 配置Spoon环境
        launcher.addInputResource(
                "C:/dataset/SpingBoot/springboot018_muying-master/springboot018_muying-master/muyingshangcheng/src/main/java");
        launcher.setSourceOutputDirectory("C:/dataset/analysis-output");
        launcher.getEnvironment().setAutoImports(true);
        launcher.getEnvironment().setCommentEnabled(true);
        launcher.getEnvironment().setCopyResources(false);
        launcher.getEnvironment().setPrettyPrinterCreator(() -> new SniperJavaPrettyPrinter(launcher.getEnvironment()));
        // launcher.getEnvironment().setPrettyPrinterCreator(() -> new
        // CustomPrettyPrinter(launcher.getEnvironment()));
        // launcher.getEnvironment()
        // .setPrettyPrinterCreator(() -> new
        // DefaultJavaPrettyPrinter(launcher.getEnvironment()));
        // 设置输入源代码路径

        try {
            // CtModel model = launcher.buildModel();
            launcher.process();
            // 重置环境状态
            launcher.prettyprint();
            generateAnalysisReport(processor);

            // 输出目录设置为其他位置，避免覆盖原始代码
            // generateAnalysisReport();

            // launcher.prettyprint();

        } catch (Exception e) {
            System.err.println("分析过程中发生错误:");
            e.printStackTrace();
            // 添加更详细的错误处理
            // handleBuildError(e);
        }
    }

    // private static void generateAnalysisReport() {
    // Map<String, List<String>> results = new HashMap<>(); // 这里应当获取实际的分析结果
    // System.out.println(results);
    // try (FileWriter writer = new FileWriter(
    // "C:\\dataset\\SpingBoot\\springboot018_muying-master\\springboot018_muying-master\\muyingshangcheng\\target\\log-analysis-report.json"))
    // {
    // new GsonBuilder().setPrettyPrinting().create().toJson(results, writer);
    // } catch (Exception e) {
    // e.printStackTrace();
    // }
    // }

    private static void generateAnalysisReport(LogAnalysisProcessor processor) {
        try (FileWriter writer = new FileWriter("C:\\dataset\\analysis-output\\log-analysis-report.json")) {
            new GsonBuilder().setPrettyPrinting().create().toJson(processor.getAnalysisResults(), writer);
            System.out.println("报告已生成");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
