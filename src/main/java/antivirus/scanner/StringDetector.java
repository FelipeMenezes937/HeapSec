package antivirus.scanner;

import java.util.*;

public class StringDetector {

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
        "password",
        "passwordfox",
        "passview",
        "browserpass",
        "netpass",
        "pwdump",
        "mimikatz",
        "lazagne",
        "pony",
        "stealer",
        "credential",
        "logins",
        "moz_logins",
        "signons",
        "encrypted",
        "decrypt",
        "firefox",
        "chrome",
        "browser",
        "savedpassword"
    };

    private static final String[] KEYLOGGER_PATTERNS = {
        "keylog",
        "keystroke",
        "keyboard",
        "hook",
        "SetWindowsHookEx",
        "GetAsyncKeyState",
        "GetKeyboardState",
        "WM_KEYDOWN",
        "WM_CHAR",
        "SendKeys",
        "SendMessage"
    };

    private static final String[] BANKER_PATTERNS = {
        "bank",
        "banking",
        "transfer",
        "creditcard",
        "credit card",
        "card number",
        "cvv",
        "expire",
        "billing",
        "account number",
        "routing number",
        "iban",
        "swift",
        "bitcoin",
        "btc",
        "wallet"
    };

    private static final String[] RAT_PATTERNS = {
        "rat",
        "remote administration",
        "backdoor",
        "trojan",
        "njrat",
        "njghost",
        "asyncrat",
        "quasar",
        "remcos",
        "metasploit",
        "cobalt",
        "powershell -nop",
        "tcpconnect",
        "reverse shell",
        "connect back"
    };

    private static final String[] CRYPTOMINER_PATTERNS = {
        "cryptonight",
        "cryptominner",
        "xmrig",
        "xmrig",
        "miner",
        "minerd",
        "hashrate",
        "submit",
        "stratum",
        "pool",
        "coin hive",
        "coinhive",
        "crypto"
    };

    private static final String[] DROPPER_PATTERNS = {
        "dropper",
        "downloader",
        "payload",
        "stager",
        "download execute",
        "iEX",
        "invoke-expression",
        "wscript",
        "mshta",
        "certutil",
        "bitsadmin",
        "powershell -e"
    };

    private static final String[] SPYWARE_PATTERNS = {
        "spyware",
        "surveillance",
        "monitor",
        "screenshot",
        "clipboard",
        "webcam",
        "microphone",
        "record",
        "dwell",
        " investigator",
        "espionage"
    };

    private static final String[] BOTNET_PATTERNS = {
        "botnet",
        "zombie",
        "ddos",
        "amplification",
        "syn flood",
        "udp flood",
        "rooter",
        "flooder",
        "bot"
    };

    private static final String[] RANSOMWARE_PATTERNS = {
        "ransom",
        "encrypted",
        "your files",
        "decrypt",
        "payment",
        "wallet",
        "locked files",
        "restore files",
        "all files encrypted",
        "unlock"
    };

    private static final int SEARCH_LIMIT = 2 * 1024 * 1024;

    private static AhoCorasick SUSPICIOUS_AC;
    private static AhoCorasick PASSWORD_AC;
    private static AhoCorasick KEYLOGGER_AC;
    private static AhoCorasick BANKER_AC;
    private static AhoCorasick RAT_AC;
    private static AhoCorasick CRYPTOMINER_AC;
    private static AhoCorasick DROPPER_AC;
    private static AhoCorasick SPYWARE_AC;
    private static AhoCorasick BOTNET_AC;
    private static AhoCorasick RANSOMWARE_AC;

    static {
        SUSPICIOUS_AC = buildAC(SUSPICIOUS_PATTERNS);
        PASSWORD_AC = buildAC(PASSWORD_STEALER_PATTERNS);
        KEYLOGGER_AC = buildAC(KEYLOGGER_PATTERNS);
        BANKER_AC = buildAC(BANKER_PATTERNS);
        RAT_AC = buildAC(RAT_PATTERNS);
        CRYPTOMINER_AC = buildAC(CRYPTOMINER_PATTERNS);
        DROPPER_AC = buildAC(DROPPER_PATTERNS);
        SPYWARE_AC = buildAC(SPYWARE_PATTERNS);
        BOTNET_AC = buildAC(BOTNET_PATTERNS);
        RANSOMWARE_AC = buildAC(RANSOMWARE_PATTERNS);
    }

    private static AhoCorasick buildAC(String[] patterns) {
        AhoCorasick ac = new AhoCorasick();
        for (String p : patterns) {
            ac.addPattern(p);
        }
        ac.build();
        return ac;
    }

    public List<String> detect(byte[] data) {
        int limit = Math.min(data.length, SEARCH_LIMIT);
        byte[] searchData = Arrays.copyOf(data, limit);
        List<String> found = SUSPICIOUS_AC.search(searchData, SUSPICIOUS_PATTERNS);
        return found.subList(0, Math.min(found.size(), 10));
    }

    public List<String> detectPasswordStealer(byte[] data) {
        int limit = Math.min(data.length, SEARCH_LIMIT);
        byte[] searchData = Arrays.copyOf(data, limit);
        List<String> found = PASSWORD_AC.search(searchData, PASSWORD_STEALER_PATTERNS);
        return found.subList(0, Math.min(found.size(), 10));
    }

    public int countPasswordStealerPatterns(byte[] data) {
        return detectPasswordStealer(data).size();
    }

    public MalwareCategory detectCategory(byte[] data) {
        int limit = Math.min(data.length, SEARCH_LIMIT);
        byte[] searchData = Arrays.copyOf(data, limit);

        int psCount = PASSWORD_AC.search(searchData, PASSWORD_STEALER_PATTERNS).size();
        int klCount = KEYLOGGER_AC.search(searchData, KEYLOGGER_PATTERNS).size();
        int bankCount = BANKER_AC.search(searchData, BANKER_PATTERNS).size();
        int ratCount = RAT_AC.search(searchData, RAT_PATTERNS).size();
        int mineCount = CRYPTOMINER_AC.search(searchData, CRYPTOMINER_PATTERNS).size();
        int dropCount = DROPPER_AC.search(searchData, DROPPER_PATTERNS).size();
        int spyCount = SPYWARE_AC.search(searchData, SPYWARE_PATTERNS).size();
        int botCount = BOTNET_AC.search(searchData, BOTNET_PATTERNS).size();
        int ranCount = RANSOMWARE_AC.search(searchData, RANSOMWARE_PATTERNS).size();

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

    public int getCategoryScore(byte[] data) {
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

    public boolean isWorthScanning(double entropy) {
        return entropy > 6.5;
    }

    public enum MalwareCategory {
        PASSWORD_STEALER,
        KEYLOGGER,
        BANKER,
        RAT,
        CRYPTOMINER,
        DROPPER,
        SPYWARE,
        BOTNET,
        RANSOMWARE,
        SUSPICIOUS,
        UNKNOWN
    }
}