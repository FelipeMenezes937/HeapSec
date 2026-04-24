package antivirus.scanner;

public class SteganographyAnalyzerTest {

    private static SteganographyAnalyzer analyzer = new SteganographyAnalyzer();
    private static int passed = 0;
    private static int failed = 0;

    private static byte[] padding64(byte[] data) {
        byte[] result = new byte[64];
        System.arraycopy(data, 0, result, 0, Math.min(data.length, 64));
        return result;
    }

    public static void main(String[] args) {
        testJPEGDetection();
        testPNGDetection();
        testGIFDetection();
        testBMPDetection();
        testPDFDetection();
        testSmallFileReturnsFalse();
        testMagicByteMismatchJPEG();
        testMagicByteMismatchPNG();
        testMagicByteMismatchPDF();
        testMagicByteMismatchexe();
        testPNGWithExtraData();
        testWAVDetection();
        testRandomDataNoDetection();
        testNullData();

        printSummary();
    }

    public static void testJPEGDetection() {
        byte[] jpegMagic = padding64(new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF, (byte)0xE0, 0x00, 0x10, (byte)0x4A, (byte)0x46});
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(jpegMagic, "image.jpg");
        check("JPEG Detection", result != null);
    }

    public static void testPNGDetection() {
        byte[] pngMagic = padding64(new byte[]{(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52});
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(pngMagic, "image.png");
        check("PNG Detection", result != null);
    }

    public static void testGIFDetection() {
        byte[] gifMagic = padding64(new byte[]{0x47, 0x49, 0x46, 0x38, 0x39, 0x61});
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(gifMagic, "image.gif");
        check("GIF Detection", result != null);
    }

    public static void testBMPDetection() {
        byte[] bmpMagic = padding64(new byte[]{0x42, 0x4D});
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(bmpMagic, "image.bmp");
        check("BMP Detection", result != null);
    }

    public static void testPDFDetection() {
        byte[] pdfMagic = padding64(new byte[]{0x25, 0x50, 0x44, 0x46, 0x25, 0x45, 0x4F, 0x46});
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(pdfMagic, "document.pdf");
        check("PDF Detection", result != null);
    }

    public static void testSmallFileReturnsFalse() {
        byte[] small = new byte[]{0x00, 0x01};
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(small, "tiny.bin");
        check("Small File Returns False", !result.isDetected());
    }

    public static void testMagicByteMismatchJPEG() {
        byte[] notAJpeg = padding64(new byte[]{(byte)0x4D, (byte)0x5A, (byte)0x90, 0x00});
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(notAJpeg, "image.jpg");
        check("Magic Mismatch JPEG", result.isDetected());
    }

    public static void testMagicByteMismatchPNG() {
        byte[] notAPng = padding64(new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF});
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(notAPng, "image.png");
        check("Magic Mismatch PNG", result.isDetected());
    }

    public static void testMagicByteMismatchPDF() {
        byte[] notAPdf = padding64(new byte[]{0x42, 0x4D});
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(notAPdf, "document.pdf");
        check("Magic Mismatch PDF", result.isDetected());
    }

    public static void testMagicByteMismatchexe() {
        byte[] exeMagic = padding64(new byte[]{(byte)0x4D, (byte)0x5A});
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(exeMagic, "malware.exe");
        check("EXE Magic No Mismatch", !result.isDetected());
    }

    public static void testPNGWithExtraData() {
        byte[] pngWithExtra = padding64(new byte[]{
            (byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10,
            0x08, 0x02, 0x00, 0x00, 0x00, (byte)0x90, (byte)0x91, 0x68, 0x36,
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
            (byte)0xAE, 0x42, 0x60, (byte)0x82,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        });
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(pngWithExtra, "hidden.png");
        check("PNG with Extra Data", result.isDetected());
    }

    public static void testWAVDetection() {
        byte[] wavMagic = padding64(new byte[]{0x52, 0x49, 0x46, 0x46});
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(wavMagic, "audio.wav");
        check("WAV Detection", result != null);
    }

    public static void testRandomDataNoDetection() {
        byte[] randomData = new byte[256];
        for (int i = 0; i < 256; i++) {
            randomData[i] = (byte)(i * 7);
        }
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(randomData, "random.bin");
        check("Random Data No Detection", !result.isDetected());
    }

    public static void testNullData() {
        byte[] zeros = new byte[256];
        SteganographyAnalyzer.SteganographyResult result = analyzer.analyze(zeros, "zeros.bin");
        check("Null Data No Detection", !result.isDetected());
    }

    private static void check(String name, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  \u001b[32m✓ PASS\u001b[0m " + name);
        } else {
            failed++;
            System.out.println("  \u001b[31m✗ FAIL\u001b[0m " + name);
        }
    }

    private static void printSummary() {
        System.out.println("\n--- " + (passed + failed) + " tests: " + passed + " passed, " + failed + " failed ---");
    }
}