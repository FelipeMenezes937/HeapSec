import antivirus.scanner.*;
import java.nio.file.Files;
import java.nio.file.Path;

public class ScoreTest {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java ScoreTest <file>");
            return;
        }
        
        Path path = Path.of(args[0]);
        byte[] data = Files.readAllBytes(path);
        
        // Test individual components
        EntropyAnalyzer entropyAnalyzer = new EntropyAnalyzer();
        double entropy = entropyAnalyzer.calculateEntropy(data);
        System.out.printf("Entropy: %.4f%n", entropy);
        
        YaraScanner yaraScanner = new YaraScanner();
        var yaraMatches = yaraScanner.scan(data);
        int yaraScore = yaraScanner.getTotalScore(data, 40);
        System.out.printf("YARA matches: %d%n", yaraMatches.size());
        System.out.printf("YARA score (if entropy > 6.5): %d%n", yaraScore);
        System.out.printf("YARA score (always): %d%n", yaraScanner.getTotalScore(data, 0));
        
        PEAnalyzer peAnalyzer = new PEAnalyzer();
        var peAnalysis = peAnalyzer.analyze(data);
        System.out.printf("Valid PE: %b%n", peAnalysis.isValidPE());
        System.out.printf("Has packer sections: %b%n", peAnalysis.hasPackerSections());
        System.out.printf("Has write+execute: %b%n", peAnalysis.hasWriteAndExecute());
        
        ExtensionChecker extensionChecker = new ExtensionChecker();
        boolean doubleExt = extensionChecker.check(path.getFileName().toString());
        System.out.printf("Double extension: %b%n", doubleExt);
        
        BoyerMooreStringDetector.MalwareCategory category = BoyerMooreStringDetector.detectCategory(data);
        int categoryScore = BoyerMooreStringDetector.getCategoryScore(data);
        System.out.printf("Category: %s%n", category);
        System.out.printf("Category score: %d%n", categoryScore);
        
        var suspicious = BoyerMooreStringDetector.detectSuspicious(data);
        var passwordStealer = BoyerMooreStringDetector.detectPasswordStealer(data);
        System.out.printf("Suspicious strings: %d%n", suspicious.size());
        System.out.printf("Password stealer strings: %d%n", passwordStealer.size());
    }
}
