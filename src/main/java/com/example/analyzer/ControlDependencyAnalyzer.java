package com.example.analyzer;

import java.util.*;

import spoon.reflect.code.*;
import spoon.reflect.declaration.*;

// ===================== 新增：控制依赖分析工具 =====================
public class ControlDependencyAnalyzer {
    /**
     * 从当前元素往上遍历父节点，收集控制结构条件（if、for、while、do-while、for-each、try-catch）
     */
    public static List<String> getControlDependencies(CtElement element) {
        List<String> ctrlDeps = new ArrayList<>();
        CtElement current = element.getParent();
        while (current != null) {
            if (current instanceof CtIf) {
                CtIf ctIf = (CtIf) current;
                ctrlDeps.add("if(" + ctIf.getCondition() + ")");
            } else if (current instanceof CtFor) {
                CtFor ctFor = (CtFor) current;
                // 注意 CtFor 中可能没有直接可用的循环条件（需视情况提取）
                ctrlDeps.add("for(" + ((CtWhile) ctFor).getLoopingExpression() + ")");
            } else if (current instanceof CtWhile) {
                CtWhile ctWhile = (CtWhile) current;
                ctrlDeps.add("while(" + ctWhile.getLoopingExpression() + ")");
            } else if (current instanceof CtDo) {
                CtDo ctDo = (CtDo) current;
                ctrlDeps.add("do-while(" + ctDo.getLoopingExpression() + ")");
            } else if (current instanceof CtForEach) {
                CtForEach ctForEach = (CtForEach) current;
                ctrlDeps.add("forEach(" + ctForEach.getExpression() + ")");
            } else if (current instanceof CtTry) {
                ctrlDeps.add("try-catch");
            }
            current = current.getParent();
        }
        return ctrlDeps;
    }
}
// ===================== end ControlDependencyAnalyzer =====================