import antivirus.scanner.EntropyAnalyzer;
import java.nio.file.Files;
import java.nio.file.Path;

public class EntropyTest {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java EntropyTest <file>");
            return;
        }
        
        Path path = Path.of(args[0]);
        byte[] data = Files.readAllBytes(path);
        EntropyAnalyzer analyzer = new EntropyAnalyzer();
        double entropy = analyzer.calculateEntropy(data);
        System.out.printf("File: %s%n", path.getFileName());
        System.out.printf("Size: %d bytes%n", data.length);
        System.out.printf("Entropy: %.4f%n", entropy);
        
        // Check if it's compressed
        boolean compressed = analyzer.isCompressed(data);
        System.out.printf("Is compressed: %b%n", compressed);
    }
}
