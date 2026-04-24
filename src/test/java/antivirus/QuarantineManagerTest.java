package antivirus.action;

import java.nio.file.*;

public class QuarantineManagerTest {

    private static QuarantineManager qm = new QuarantineManager();
    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        testConstructor();
        testQuarantineNonexistentFile();
        testDeleteNonexistentFile();
        testDeleteBlocksSystemDirectory();
        testDeleteBlocksQuarantineDirectory();
        testListQuarantined();

        printSummary();
    }

    public static void testConstructor() {
        check("Instantiate", qm != null);
    }

    public static void testQuarantineNonexistentFile() {
        boolean result = qm.quarantine("/nonexistent/file.exe");
        check("Quarantine Non-existent", !result);
    }

    public static void testDeleteNonexistentFile() {
        boolean result = qm.delete("/nonexistent/file.exe");
        check("Delete Non-existent", !result);
    }

    public static void testDeleteBlocksSystemDirectory() {
        String home = System.getProperty("user.home");
        String systemPath = home + "/antivirus/safe.exe";
        boolean result = qm.delete(systemPath);
        check("Block System Delete", !result);
    }

    public static void testDeleteBlocksQuarantineDirectory() {
        String home = System.getProperty("user.home");
        String quarantinePath = home + "/.antivirus/test.exe";
        boolean result = qm.delete(quarantinePath);
        check("Block Quarantine Delete", !result);
    }

    public static void testListQuarantined() {
        try {
            qm.listQuarantined();
            check("List Quarantined", true);
        } catch (Exception e) {
            check("List Quarantined", false);
        }
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