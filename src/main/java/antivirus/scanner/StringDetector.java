package antivirus.scanner;

import java.util.ArrayList;
import java.util.List;

public class StringDetector {

    private static final String[] SUSPICIOUS_PATTERNS = {
        "http://",
        "cmd.exe",
        "powershell",
        "wscript",
        "cscript",
        "certutil",
        "bitsadmin",
        "whoami",
        "net user",
        "reg add",
        "vssadmin",
        "mimikatz",
        "Base64",
        "encodedcommand",
        "downloadstring",
        "invoke-webrequest",
        "new-object net.webclient",
        "IEX new-object",
        "eval(",
        "exec(",
        "system(",
        "passthru"
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
        "encrypt",
        "encrypted",
        "your files",
        "decrypt",
        "bitcoin",
        "btc",
        "payment",
        "wallet",
        "locked",
        "locked files",
        "restore"
    };

    public List<String> detect(byte[] data) {
        List<String> found = new ArrayList<>();
        String content = new String(data);
        
        for (String pattern : SUSPICIOUS_PATTERNS) {
            if (content.toLowerCase().contains(pattern.toLowerCase())) {
                found.add(pattern);
            }
        }
        
        return found;
    }

    public List<String> detectPasswordStealer(byte[] data) {
        List<String> found = new ArrayList<>();
        String content = new String(data);
        for (String pattern : PASSWORD_STEALER_PATTERNS) {
            if (content.toLowerCase().contains(pattern.toLowerCase())) {
                found.add(pattern);
            }
        }
        return found;
    }

    public int countPasswordStealerPatterns(byte[] data) {
        return detectPasswordStealer(data).size();
    }

    public MalwareCategory detectCategory(byte[] data) {
        String content = new String(data).toLowerCase();
        int psCount = countPasswordStealerPatterns(data);
        int klCount = countPatterns(data, KEYLOGGER_PATTERNS);
        int bankCount = countPatterns(data, BANKER_PATTERNS);
        int ratCount = countPatterns(data, RAT_PATTERNS);
        int mineCount = countPatterns(data, CRYPTOMINER_PATTERNS);
        int dropCount = countPatterns(data, DROPPER_PATTERNS);
        int spyCount = countPatterns(data, SPYWARE_PATTERNS);
        int botCount = countPatterns(data, BOTNET_PATTERNS);
        int ranCount = countPatterns(data, RANSOMWARE_PATTERNS);

        if (psCount >= 3) return MalwareCategory.PASSWORD_STEALER;
        if (ratCount >= 3) return MalwareCategory.RAT;
        if (ranCount >= 3) return MalwareCategory.RANSOMWARE;
        if (mineCount >= 3) return MalwareCategory.CRYPTOMINER;
        if (bankCount >= 3) return MalwareCategory.BANKER;
        if (klCount >= 3) return MalwareCategory.KEYLOGGER;
        if (dropCount >= 3) return MalwareCategory.DROPPER;
        if (spyCount >= 3) return MalwareCategory.SPYWARE;
        if (botCount >= 3) return MalwareCategory.BOTNET;
        if (psCount > 0 || ratCount > 0 || ranCount > 0 || mineCount > 0) {
            return MalwareCategory.SUSPICIOUS;
        }
        return MalwareCategory.UNKNOWN;
    }

    private int countPatterns(byte[] data, String[] patterns) {
        String content = new String(data).toLowerCase();
        int count = 0;
        for (String pattern : patterns) {
            if (content.contains(pattern.toLowerCase())) {
                count++;
            }
        }
        return count;
    }

    public int getCategoryScore(byte[] data) {
        MalwareCategory cat = detectCategory(data);
        switch (cat) {
            case PASSWORD_STEALER: return 60;
            case RANSOMWARE: return 80;
            case RAT: return 70;
            case BANKER: return 60;
            case CRYPTOMINER: return 50;
            case KEYLOGGER: return 50;
            case BOTNET: return 50;
            case SPYWARE: return 45;
            case DROPPER: return 40;
            case SUSPICIOUS: return 30;
            default: return 0;
        }
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