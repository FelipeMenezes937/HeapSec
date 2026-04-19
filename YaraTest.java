import antivirus.scanner.YaraScanner;
import java.nio.file.Files;
import java.nio.file.Path;

public class YaraTest {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java YaraTest <file>");
            return;
        }
        
        Path path = Path.of(args[0]);
        byte[] data = Files.readAllBytes(path);
        YaraScanner scanner = new YaraScanner();
        System.out.println("YARA Rules loaded: " + scanner.getRuleCount());
        
        var matches = scanner.scan(data);
        System.out.println("Matches found: " + matches.size());
        for (String match : matches) {
            System.out.println("  - " + match);
        }
        
        int score = scanner.getTotalScore(data);
        System.out.println("Total score: " + score);
    }
}
