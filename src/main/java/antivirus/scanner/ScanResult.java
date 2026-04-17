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
    private final List<String> threats;
    private final boolean quarantined;
    private final boolean processKilled;

    public ScanResult(String fileName, long size, double entropy, 
                      List<String> suspiciousStrings, boolean doubleExtension,
                      boolean isPe, String score, List<String> threats,
                      boolean quarantined, boolean processKilled) {
        this.fileName = fileName;
        this.size = size;
        this.entropy = entropy;
        this.suspiciousStrings = suspiciousStrings;
        this.doubleExtension = doubleExtension;
        this.isPe = isPe;
        this.score = score;
        this.threats = threats;
        this.quarantined = quarantined;
        this.processKilled = processKilled;
    }

    public String getFileName() { return fileName; }
    public long getSize() { return size; }
    public double getEntropy() { return entropy; }
    public List<String> getSuspiciousStrings() { return suspiciousStrings; }
    public boolean isDoubleExtension() { return doubleExtension; }
    public boolean isPe() { return isPe; }
    public String getScore() { return score; }
    public List<String> getThreats() { return threats; }
    public boolean isQuarantined() { return quarantined; }
    public boolean isProcessKilled() { return processKilled; }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Scan Result ===\n");
        sb.append("File: ").append(fileName).append("\n");
        sb.append("Size: ").append(size).append(" bytes\n");
        sb.append("Entropy: ").append(String.format("%.2f", entropy)).append("\n");
        sb.append("Is PE: ").append(isPe).append("\n");
        sb.append("Double Extension: ").append(doubleExtension).append("\n");
        sb.append("Suspicious Strings: ").append(suspiciousStrings.size() > 0 ? suspiciousStrings : "None").append("\n");
        sb.append("Threat Level: ").append(score).append("\n");
        if (!threats.isEmpty()) {
            sb.append("Threats:\n");
            for (String threat : threats) {
                sb.append("  - ").append(threat).append("\n");
            }
        }
        if (quarantined) sb.append(">>> QUARENTENA: Arquivo movido\n");
        if (processKilled) sb.append(">>> Acao: Processo encerrado\n");
        return sb.toString();
    }
}