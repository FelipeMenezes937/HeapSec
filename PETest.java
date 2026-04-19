import antivirus.scanner.PEAnalyzer;
import java.nio.file.Files;
import java.nio.file.Path;

public class PETest {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java PETest <file>");
            return;
        }
        
        Path path = Path.of(args[0]);
        byte[] data = Files.readAllBytes(path);
        PEAnalyzer analyzer = new PEAnalyzer();
        var peAnalysis = analyzer.analyze(data);
        System.out.printf("File: %s%n", path.getFileName());
        System.out.printf("Size: %d bytes%n", data.length);
        System.out.printf("Valid PE: %b%n", peAnalysis.isValidPE());
        System.out.printf("Has Packer Sections: %b%n", peAnalysis.hasPackerSections());
        System.out.printf("Has Write+Execute: %b%n", peAnalysis.hasWriteAndExecute());
    }
}
