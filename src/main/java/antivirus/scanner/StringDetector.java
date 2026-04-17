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
}