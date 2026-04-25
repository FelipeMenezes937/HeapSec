package antivirus;

import java.nio.file.*;
import antivirus.scanner.*;

public class DebugWatch {

    public static void main(String[] args) throws Exception {
        Path p = Path.of("/home/felipe/Downloads/passwordfox.exe");
        byte[] data = Files.readAllBytes(p);
        
        System.out.println("=== Watch Mode Debug ===");
        System.out.println("File: " + p.getFileName());
        System.out.println("Size: " + data.length);
        
        YaraScanner yara = new YaraScanner();
        var matches = yara.scan(data);
        int score = yara.getTotalScore(data, 0);
        System.out.println("YARA matches: " + matches);
        System.out.println("YARA score: " + score);
        
        EntropyAnalyzer ea = new EntropyAnalyzer();
        double entropy = ea.calculateEntropy(data);
        System.out.println("Entropy: " + entropy);
    }
}