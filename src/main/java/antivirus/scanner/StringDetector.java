package antivirus.scanner;

import java.util.List;

public class StringDetector {

    private static final int SEARCH_LIMIT = 2 * 1024 * 1024;

    public List<String> detect(byte[] data) {
        return BoyerMooreStringDetector.detectSuspicious(data);
    }

    public List<String> detectPasswordStealer(byte[] data) {
        return BoyerMooreStringDetector.detectPasswordStealer(data);
    }

    public int countPasswordStealerPatterns(byte[] data) {
        return BoyerMooreStringDetector.detectPasswordStealer(data).size();
    }

    public BoyerMooreStringDetector.MalwareCategory detectCategory(byte[] data) {
        return BoyerMooreStringDetector.detectCategory(data);
    }

    public int getCategoryScore(byte[] data) {
        return BoyerMooreStringDetector.getCategoryScore(data);
    }

    public boolean isWorthScanning(double entropy) {
        return entropy > 6.5;
    }
}