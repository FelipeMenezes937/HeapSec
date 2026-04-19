package antivirus.scanner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class HeuristicAnalyzerTest {
    public static void main(String[] args) throws Exception {
        HeuristicAnalyzer analyzer = new HeuristicAnalyzer();
        
        // Test 1: EICAR-like string (should trigger string combo? Actually EICAR is a specific string)
        // We'll test with a file that has suspicious string combinations
        
        // Create a test file with "powershell download"
        String testContent = "This is a test file with powershell download command";
        byte[] data = testContent.getBytes();
        Path tempFile = Files.createTempFile("test", ".txt");
        Files.write(tempFile, data);
        
        HeuristicAnalyzer.HeuristicResult result = analyzer.analyze(data, tempFile, tempFile.getFileName().toString());
        System.out.println("Test 1 - powershell download:");
        System.out.println(result);
        
        // Clean up
        Files.deleteIfExists(tempFile);
        
        // Test 2: High entropy file
        byte[] highEntropyData = new byte[1000];
        java.util.Random rand = new java.util.Random();
        rand.nextBytes(highEntropyData);
        HeuristicAnalyzer.HeuristicResult result2 = analyzer.analyze(highEntropyData, Path.of("high_entropy.bin"), "high_entropy.bin");
        System.out.println("\nTest 2 - high entropy:");
        System.out.println(result2);
        
        // Test 3: File with signed attribute (we don't have real signing, so just testing the logic)
        // We'll skip this for now because our isFileSigned always returns false
        
        // Test 4: Combo of multiple things
        String testContent4 = "powershell -nop -exec bypass -EncodedCommand aGVsbG8gd29ybGQ=";
        byte[] data4 = testContent4.getBytes();
        Path tempFile4 = Files.createTempFile("test4", ".exe");
        Files.write(tempFile4, data4);
        
        HeuristicAnalyzer.HeuristicResult result4 = analyzer.analyze(data4, tempFile4, tempFile4.getFileName().toString());
        System.out.println("\nTest 4 - powershell with encoded command (exe file):");
        System.out.println(result4);
        
        // Clean up
        Files.deleteIfExists(tempFile4);
    }
}