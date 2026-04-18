package antivirus.scanner;

import java.util.*;

public class BoyerMooreStringDetector {

    private static final String[] SUSPICIOUS_PATTERNS = {
        "cmd.exe /c",
        "powershell -nop",
        "wscript ",
        "cscript ",
        "certutil -decode",
        "bitsadmin /transfer",
        "whoami /all",
        "reg add HKLM",
        "vssadmin delete",
        "mimikatz",
        "encodedcommand",
        "downloadstring",
        "invoke-webrequest",
        "iex ",
        "invoke-expression",
        "eval(",
        "exec(",
        "system(",
        "passthru",
        "CreateObject",
        "WScript.Shell",
        "ShellExecute"
    };

    private static final String[] PASSWORD_STEALER_PATTERNS = {
        "password", "passwordfox", "passview", "browserpass", "netpass",
        "pwdump", "mimikatz", "lazagne", "pony", "stealer", "credential",
        "logins", "moz_logins", "signons", "encrypted", "decrypt",
        "firefox", "chrome", "browser", "savedpassword"
    };

    private static final String[] KEYLOGGER_PATTERNS = {
        "keylog", "keystroke", "keyboard", "hook", "SetWindowsHookEx",
        "GetAsyncKeyState", "GetKeyboardState", "WM_KEYDOWN", "WM_CHAR",
        "SendKeys", "SendMessage"
    };

    private static final String[] BANKER_PATTERNS = {
        "bank", "banking", "transfer", "creditcard", "credit card",
        "card number", "cvv", "expire", "billing", "account number",
        "routing number", "iban", "swift", "bitcoin", "btc", "wallet"
    };

    private static final String[] RAT_PATTERNS = {
        "rat", "remote administration", "backdoor", "trojan", "njrat",
        "njghost", "asyncrat", "quasar", "remcos", "metasploit", "cobalt",
        "powershell -nop", "tcpconnect", "reverse shell", "connect back"
    };

    private static final String[] CRYPTOMINER_PATTERNS = {
        "cryptonight", "cryptominner", "xmrig", "miner", "minerd",
        "hashrate", "submit", "stratum", "pool", "coin hive", "coinhive", "crypto"
    };

    private static final String[] DROPPER_PATTERNS = {
        "dropper", "downloader", "payload", "stager", "download execute",
        "iEX", "invoke-expression", "wscript", "mshta", "certutil",
        "bitsadmin", "powershell -e"
    };

    private static final String[] SPYWARE_PATTERNS = {
        "spyware", "surveillance", "monitor", "screenshot", "clipboard",
        "webcam", "microphone", "record", "dwell", " investigator", "espionage"
    };

    private static final String[] BOTNET_PATTERNS = {
        "botnet", "zombie", "ddos", "amplification", "syn flood",
        "udp flood", "rooter", "flooder", "bot"
    };

    private static final String[] RANSOMWARE_PATTERNS = {
        "ransom", "encrypted", "your files", "decrypt", "payment", "wallet",
        "locked files", "restore files", "all files encrypted", "unlock"
    };

    private static final int SEARCH_LIMIT = 2 * 1024 * 1024;

    private static int[] buildBadCharTable(String pattern) {
        int[] table = new int[256];
        Arrays.fill(table, -1);
        for (int i = 0; i < pattern.length() - 1; i++) {
            table[pattern.charAt(i) & 0xFF] = i;
        }
        return table;
    }

    private static boolean boyerMooreSearch(byte[] data, String pattern) {
        int[] badChar = buildBadCharTable(pattern);
        byte[] patBytes = pattern.toLowerCase().getBytes();
        int m = patBytes.length;
        int n = data.length;
        int limit = Math.min(n, SEARCH_LIMIT);

        int s = 0;
        while (s <= limit - m) {
            int j = m - 1;
            while (j >= 0) {
                byte dataByte = data[s + j];
                if (dataByte >= 'A' && dataByte <= 'Z') dataByte = (byte) (dataByte + 32);
                if (dataByte != patBytes[j]) break;
                j--;
            }
            if (j < 0) return true;
            else s += Math.max(1, j - badChar[data[s + j] & 0xFF]);
        }
        return false;
    }

    public static List<String> detectSuspicious(byte[] data) {
        List<String> found = new ArrayList<>();
        for (String pattern : SUSPICIOUS_PATTERNS) {
            if (boyerMooreSearch(data, pattern)) {
                found.add(pattern);
                if (found.size() >= 10) break;
            }
        }
        return found;
    }

    public static List<String> detectPasswordStealer(byte[] data) {
        List<String> found = new ArrayList<>();
        for (String pattern : PASSWORD_STEALER_PATTERNS) {
            if (boyerMooreSearch(data, pattern)) {
                found.add(pattern);
                if (found.size() >= 10) break;
            }
        }
        return found;
    }

    public static int countPatterns(byte[] data, String[] patterns) {
        int count = 0;
        for (String pattern : patterns) {
            if (boyerMooreSearch(data, pattern)) {
                count++;
                if (count >= 5) break;
            }
        }
        return count;
    }

    public static MalwareCategory detectCategory(byte[] data) {
        int psCount = countPatterns(data, PASSWORD_STEALER_PATTERNS);
        int klCount = countPatterns(data, KEYLOGGER_PATTERNS);
        int bankCount = countPatterns(data, BANKER_PATTERNS);
        int ratCount = countPatterns(data, RAT_PATTERNS);
        int mineCount = countPatterns(data, CRYPTOMINER_PATTERNS);
        int dropCount = countPatterns(data, DROPPER_PATTERNS);
        int spyCount = countPatterns(data, SPYWARE_PATTERNS);
        int botCount = countPatterns(data, BOTNET_PATTERNS);
        int ranCount = countPatterns(data, RANSOMWARE_PATTERNS);

        if (psCount >= 8) return MalwareCategory.PASSWORD_STEALER;
        if (ratCount >= 8) return MalwareCategory.RAT;
        if (ranCount >= 8) return MalwareCategory.RANSOMWARE;
        if (mineCount >= 8) return MalwareCategory.CRYPTOMINER;
        if (bankCount >= 10) return MalwareCategory.BANKER;
        if (klCount >= 8) return MalwareCategory.KEYLOGGER;
        if (dropCount >= 8) return MalwareCategory.DROPPER;
        if (spyCount >= 8) return MalwareCategory.SPYWARE;
        if (botCount >= 8) return MalwareCategory.BOTNET;
        return MalwareCategory.UNKNOWN;
    }

    public static int getCategoryScore(byte[] data) {
        MalwareCategory cat = detectCategory(data);
        switch (cat) {
            case PASSWORD_STEALER: return 50;
            case RANSOMWARE: return 70;
            case RAT: return 60;
            case BANKER: return 40;
            case CRYPTOMINER: return 40;
            case KEYLOGGER: return 40;
            case BOTNET: return 40;
            case SPYWARE: return 35;
            case DROPPER: return 30;
            default: return 0;
        }
    }

    public enum MalwareCategory {
        PASSWORD_STEALER, KEYLOGGER, BANKER, RAT, CRYPTOMINER,
        DROPPER, SPYWARE, BOTNET, RANSOMWARE, SUSPICIOUS, UNKNOWN
    }
}