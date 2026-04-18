package antivirus.scanner;

import java.util.List;

public class ScanResult {
    private final String fileName;
    private final long size;
    private final double entropy;
    private final List<String> suspiciousStrings;
    private final boolean doubleExtension;
    private final boolean isPe;
    private final String score;
    private final int scoreValue;
    private final List<String> threats;
    private final boolean quarantined;
    private final boolean processKilled;
    private final boolean critical;

    public ScanResult(String fileName, long size, double entropy, 
                      List<String> suspiciousStrings, boolean doubleExtension,
                      boolean isPe, String score, List<String> threats,
                      boolean quarantined, boolean processKilled) {
        this(fileName, size, entropy, suspiciousStrings, doubleExtension,
             isPe, score, 0, threats, quarantined, processKilled);
    }

    public ScanResult(String fileName, long size, double entropy, 
                      List<String> suspiciousStrings, boolean doubleExtension,
                      boolean isPe, String score, int scoreValue, List<String> threats,
                      boolean quarantined, boolean processKilled) {
        this(fileName, size, entropy, suspiciousStrings, doubleExtension,
             isPe, score, scoreValue, threats, quarantined, processKilled, scoreValue >= 120);
    }

    public ScanResult(String fileName, long size, double entropy, 
                      List<String> suspiciousStrings, boolean doubleExtension,
                      boolean isPe, String score, int scoreValue, List<String> threats,
                      boolean quarantined, boolean processKilled, boolean critical) {
        this.fileName = fileName;
        this.size = size;
        this.entropy = entropy;
        this.suspiciousStrings = suspiciousStrings;
        this.doubleExtension = doubleExtension;
        this.isPe = isPe;
        this.score = score;
        this.scoreValue = scoreValue;
        this.threats = threats;
        this.quarantined = quarantined;
        this.processKilled = processKilled;
        this.critical = critical;
    }

    public String getFileName() { return fileName; }
    public long getSize() { return size; }
    public double getEntropy() { return entropy; }
    public List<String> getSuspiciousStrings() { return suspiciousStrings; }
    public boolean isDoubleExtension() { return doubleExtension; }
    public boolean isPe() { return isPe; }
    public String getScore() { return score; }
    public int getScoreValue() { return scoreValue; }
    public List<String> getThreats() { return threats; }
    public boolean isQuarantined() { return quarantined; }
    public boolean isProcessKilled() { return processKilled; }
    public boolean isCritical() { return critical; }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("┌─────────────────────────────────┐\n");
        sb.append("│  SCAN RESULT                    │\n");
        sb.append("├─────────────────────────────────┤\n");
        sb.append("│ name: ").append(fileName).append("\n");
        sb.append("│ size: ").append(formatSize(size)).append("\n");
        sb.append("│ entropy: ").append(String.format("%.2f", entropy)).append("\n");
        sb.append("├─────────────────────────────────┤\n");
        
        String badge = getBadge();
        sb.append("│ status: ").append(badge).append("\n");
        
        if (!threats.isEmpty()) {
            sb.append("├─────────────────────────────────┤\n");
            sb.append("│ threats:                        │\n");
            for (String t : threats) {
                if (t.length() > 30) {
                    sb.append("│   • ").append(t.substring(0, 27)).append("... │\n");
                } else {
                    sb.append("│   • ").append(t).append("\n");
                }
            }
        }
        sb.append("└─────────────────────────────────┘\n");
        return sb.toString();
    }
    
    private String getBadge() {
        if (score == null) return "? DESCONHECIDO";
        if (score.equals("CRITICO")) return "⚠ CRITICO";
        if (score.equals("ALTO")) return "✱ ALTO";
        if (score.equals("MEDIO")) return "~ MEDIO";
        if (score.equals("BAIXO")) return ". BAIXO";
        return "✓ SEGURO";
    }
    
    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
    }
}