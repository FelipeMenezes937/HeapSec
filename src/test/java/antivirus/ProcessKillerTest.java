package antivirus.action;

public class ProcessKillerTest {

    private static ProcessKiller killer = new ProcessKiller();
    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        testKillByPathBlocksSystemPath();
        testKillByPathBlocksUserQuarantinePath();
        testKillByPathValidation();
        testConstructor();
        testKillByPathWithNull();
        testKillByPathWithEmptyString();

        printSummary();
    }

    public static void testKillByPathBlocksSystemPath() {
        String home = System.getProperty("user.home");
        String safePath = home + "/antivirus/safe.exe";
        boolean result = killer.killByPath(safePath);
        check("Block System Path", !result);
    }

    public static void testKillByPathBlocksUserQuarantinePath() {
        String home = System.getProperty("user.home");
        String quarantinePath = home + "/.antivirus/test.exe";
        boolean result = killer.killByPath(quarantinePath);
        check("Block Quarantine Path", !result);
    }

    public static void testKillByPathValidation() {
        boolean result = killer.killByPath("/nonexistent/file.exe");
        check("Non-existent File", !result);
    }

    public static void testConstructor() {
        ProcessKiller pk = new ProcessKiller();
        check("Instantiate", pk != null);
    }

    public static void testKillByPathWithNull() {
        boolean result = killer.killByPath(null);
        check("Null Path", !result);
    }

    public static void testKillByPathWithEmptyString() {
        boolean result = killer.killByPath("");
        check("Empty String", !result);
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