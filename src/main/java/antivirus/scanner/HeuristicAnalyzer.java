package antivirus.scanner;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class HeuristicAnalyzer {

    private List<Rule> rules;
    private static final String RULES_PATH = "src/main/resources/rules/heuristic_rules.json";

    public HeuristicAnalyzer() {
        this.rules = new ArrayList<>();
        loadRules();
    }

    private void loadRules() {
        try {
            Path path = Path.of(RULES_PATH);
            if (!Files.exists(path)) {
                path = Path.of(System.getProperty("user.home") + "/.antivirus/rules/heuristic_rules.json");
            }
            if (Files.exists(path)) {
                String content = Files.readString(path);
                parseJsonRules(content);
            }
        } catch (Exception e) {
            loadDefaultRules();
        }
        if (rules.isEmpty()) {
            loadDefaultRules();
        }
    }

    private void parseJsonRules(String json) {
        try {
            json = json.replaceAll("\\s+", " ");
            String ruleSection = json.substring(json.indexOf("\"rules\"") + 8);
            ruleSection = ruleSection.substring(ruleSection.indexOf("[") + 1);
            ruleSection = ruleSection.substring(0, ruleSection.lastIndexOf("]"));

            int braceCount = 0;
            int start = 0;
            boolean inString = false;

            for (int i = 0; i < ruleSection.length(); i++) {
                char c = ruleSection.charAt(i);
                if (c == '"' && (i == 0 || ruleSection.charAt(i - 1) != '\\')) {
                    inString = !inString;
                }
                if (!inString) {
                    if (c == '{') braceCount++;
                    if (c == '}') {
                        braceCount--;
                        if (braceCount == 0) {
                            String ruleJson = ruleSection.substring(start, i + 1).trim();
                            Rule rule = parseRule(ruleJson);
                            if (rule != null) {
                                rules.add(rule);
                            }
                            start = i + 1;
                            while (start < ruleSection.length() && ruleSection.charAt(start) == ',') {
                                start++;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            loadDefaultRules();
        }
    }

    private Rule parseRule(String json) {
        try {
            String type = extractString(json, "type");
            if (type == null) return null;

            Rule rule = new Rule();
            rule.type = type;

            if (json.contains("\"score\":")) {
                String scoreStr = json.substring(json.indexOf("\"score\":") + 8);
                scoreStr = scoreStr.replaceAll("[^0-9-]", "");
                rule.score = Integer.parseInt(scoreStr);
            }

            switch (type) {
                case "string_combo":
                case "imports":
                    rule.conditions = new ArrayList<>();
                    int idx = json.indexOf("\"conditions\"");
                    if (idx >= 0) {
                        String condSection = json.substring(idx);
                        int arrStart = condSection.indexOf("[");
                        int arrEnd = condSection.lastIndexOf("]");
                        if (arrStart >= 0 && arrEnd > arrStart) {
                            String arr = condSection.substring(arrStart + 1, arrEnd);
                            String[] parts = arr.split(",");
                            for (String p : parts) {
                                String val = p.trim().replace("\"", "").replace("\\", "");
                                if (!val.isEmpty()) {
                                    rule.conditions.add(val);
                                }
                            }
                        }
                    }
                    break;

                case "entropy":
                    idx = json.indexOf("\"threshold\":");
                    if (idx >= 0) {
                        String threshStr = json.substring(idx + 12);
                        threshStr = threshStr.replaceAll("[^0-9.]", "");
                        rule.threshold = Double.parseDouble(threshStr);
                    }
                    break;

                case "signed":
                    idx = json.indexOf("\"value\":");
                    if (idx >= 0) {
                        String valStr = json.substring(idx + 8);
                        rule.value = valStr.trim().startsWith("true");
                    }
                    break;

                case "extension_mismatch":
                case "size_anomaly":
                    break;
            }

            return rule;
        } catch (Exception e) {
            return null;
        }
    }

    private String extractString(String json, String key) {
        try {
            int idx = json.indexOf("\"" + key + "\"");
            if (idx < 0) return null;
            String section = json.substring(idx);
            int colon = section.indexOf(":");
            int start = section.indexOf("\"", colon) + 1;
            int end = section.indexOf("\"", start);
            return section.substring(start, end);
        } catch (Exception e) {
            return null;
        }
    }

    private void loadDefaultRules() {
        addRule("string_combo", new String[]{"powershell", "download"}, 3);
        addRule("string_combo", new String[]{"cmd", "exec"}, 3);
        addRule("string_combo", new String[]{"base64", "decode"}, 3);
        addRule("entropy", 7.2, 2);
        addRule("entropy", 7.5, 3);
        addRule("imports", new String[]{"VirtualAlloc"}, 3);
        addRule("imports", new String[]{"WriteProcessMemory"}, 4);
        addRule("imports", new String[]{"CreateRemoteThread"}, 4);
        addRule("extension_mismatch", 5);
        addRule("size_anomaly", 2);
        addRule("signed", true, -3);
    }

    private void addRule(String type, String[] conditions, int score) {
        Rule rule = new Rule();
        rule.type = type;
        rule.conditions = Arrays.asList(conditions);
        rule.score = score;
        rules.add(rule);
    }

    private void addRule(String type, double threshold, int score) {
        Rule rule = new Rule();
        rule.type = type;
        rule.threshold = threshold;
        rule.score = score;
        rules.add(rule);
    }

    private void addRule(String type, boolean value, int score) {
        Rule rule = new Rule();
        rule.type = type;
        rule.value = value;
        rule.score = score;
        rules.add(rule);
    }

    private void addRule(String type, int score) {
        Rule rule = new Rule();
        rule.type = type;
        rule.score = score;
        rules.add(rule);
    }

    public HeuristicResult analyze(byte[] data, Path filePath, String fileName) {
        int score = 0;
        List<String> reasons = new ArrayList<>();

        String content = new String(data, 0, Math.min(data.length, 512 * 1024));
        String lowerContent = content.toLowerCase();

        for (Rule rule : rules) {
            int ruleScore = applyRule(rule, data, lowerContent, filePath, fileName);
            if (ruleScore != 0) {
                score += ruleScore;
                reasons.add(buildReason(rule, ruleScore));
            }
        }

        String classification;
        if (score >= 8) {
            classification = "malicioso";
        } else if (score >= 4) {
            classification = "suspeito";
        } else {
            classification = "limpo";
        }

        return new HeuristicResult(score, classification, reasons);
    }

    private int applyRule(Rule rule, byte[] data, String content, Path filePath, String fileName) {
        switch (rule.type) {
            case "string_combo":
                return checkStringCombo(content, rule.conditions) ? rule.score : 0;

            case "entropy":
                double entropy = calculateEntropy(data);
                return entropy > rule.threshold ? rule.score : 0;

            case "imports":
                return checkSuspiciousImports(content, rule.conditions) ? rule.score : 0;

            case "extension_mismatch":
                return checkExtensionMismatch(filePath, fileName) ? rule.score : 0;

            case "size_anomaly":
                return checkSizeAnomaly(filePath) ? rule.score : 0;

            case "signed":
                return isFileSigned(filePath) ? rule.score : 0;
        }
        return 0;
    }

    private boolean checkStringCombo(String content, List<String> conditions) {
        for (String cond : conditions) {
            if (!content.contains(cond.toLowerCase())) {
                return false;
            }
        }
        return true;
    }

    private double calculateEntropy(byte[] data) {
        if (data == null || data.length == 0) return 0.0;
        int[] freq = new int[256];
        for (byte b : data) {
            freq[b & 0xFF]++;
        }
        double entropy = 0.0;
        int len = data.length;
        for (int i = 0; i < 256; i++) {
            if (freq[i] > 0) {
                double p = (double) freq[i] / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    private boolean checkSuspiciousImports(String content, List<String> imports) {
        content = content.toUpperCase();
        for (String imp : imports) {
            if (content.contains(imp.toUpperCase())) {
                return true;
            }
        }
        return false;
    }

    private boolean checkExtensionMismatch(Path filePath, String fileName) {
        String lowerName = fileName.toLowerCase();
        if (!lowerName.endsWith(".exe") && !lowerName.endsWith(".dll") &&
            !lowerName.endsWith(".scr") && !lowerName.endsWith(".sys")) {
            return false;
        }
        try {
            byte[] header = Files.readAllBytes(filePath);
            if (header.length < 4) return false;
            int magic = ((header[0] & 0xFF) << 24) |
                        ((header[1] & 0xFF) << 16) |
                        ((header[2] & 0xFF) << 8) |
                        (header[3] & 0xFF);
            if (magic == 0xFFD8FFE0 || magic == 0xFFD8FFE1 ||
                magic == 0x89504E47 || magic == 0x47494638 ||
                magic == 0x504B0304 || magic == 0x504B0506 ||
                magic == 0x25504446) {
                return true;
            }
        } catch (IOException e) {}
        return false;
    }

    private boolean checkSizeAnomaly(Path filePath) {
        try {
            long size = Files.size(filePath);
            String fileName = filePath.getFileName().toString().toLowerCase();
            if ((fileName.endsWith(".exe") || fileName.endsWith(".dll")) && size < 1024) {
                return true;
            }
            if (size > 100 * 1024 * 1024) {
                return true;
            }
        } catch (IOException e) {}
        return false;
    }

    private boolean isFileSigned(Path filePath) {
        return false;
    }

    private String buildReason(Rule rule, int ruleScore) {
        String reason;
        switch (rule.type) {
            case "string_combo":
                reason = "string_combo:" + String.join("+", rule.conditions);
                break;
            case "entropy":
                reason = String.format("entropy>%.1f", rule.threshold);
                break;
            case "imports":
                reason = "imports:" + String.join(",", rule.conditions);
                break;
            case "extension_mismatch":
                reason = "extension_mismatch";
                break;
            case "size_anomaly":
                reason = "size_anomaly";
                break;
            case "signed":
                reason = "signed";
                break;
            default:
                reason = rule.type;
        }
        return reason + "(" + (ruleScore >= 0 ? "+" : "") + ruleScore + ")";
    }

    private static class Rule {
        String type;
        int score;
        List<String> conditions;
        double threshold;
        boolean value;
    }

    public static class HeuristicResult {
        private final int score;
        private final String classification;
        private final List<String> reasons;

        public HeuristicResult(int score, String classification, List<String> reasons) {
            this.score = score;
            this.classification = classification;
            this.reasons = reasons;
        }

        public int getScore() {
            return score;
        }

        public String getClassification() {
            return classification;
        }

        public List<String> getReasons() {
            return reasons;
        }

        public boolean isMalicious() {
            return score >= 8;
        }

        public boolean isSuspicious() {
            return score >= 4 && score < 8;
        }

        public boolean isClean() {
            return score < 4;
        }

        @Override
        public String toString() {
            return String.format("HeuristicResult{score=%d, classification=%s, reasons=%s}",
                score, classification, reasons);
        }
    }
}