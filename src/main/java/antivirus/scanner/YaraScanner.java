package antivirus.scanner;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.*;

public class YaraScanner {

    private final Map<String, Integer> ruleScores = new ConcurrentHashMap<>();
    private Pattern combinedPattern;
    private int ruleCount = 0;

    public YaraScanner() {
        loadDefaultRules();
        loadUserRules();
        buildCombinedPattern();
    }

    private void addRule(String name, int score) {
        ruleScores.put(name.toLowerCase(), score);
        ruleCount++;
    }

    private void buildCombinedPattern() {
        if (ruleScores.isEmpty()) return;
        StringBuilder sb = new StringBuilder("(?i)");
        boolean first = true;
        for (String rule : ruleScores.keySet()) {
            if (!first) sb.append("|");
            sb.append(Pattern.quote(rule));
            first = false;
        }
        try {
            combinedPattern = Pattern.compile(sb.toString());
        } catch (Exception e) {
            combinedPattern = null;
        }
    }

    public int getRuleCount() {
        return ruleCount;
    }

    public List<String> scan(byte[] data) {
        List<String> matched = new ArrayList<>();
        if (combinedPattern == null) return matched;
        
        String text = new String(data);
        Matcher m = combinedPattern.matcher(text);
        Set<String> found = new HashSet<>();
        
        while (m.find()) {
            String match = m.group();
            String lower = match.toLowerCase();
            for (Map.Entry<String, Integer> entry : ruleScores.entrySet()) {
                if (lower.contains(entry.getKey().toLowerCase())) {
                    found.add(entry.getKey() + ":" + entry.getValue());
                }
            }
        }
        matched.addAll(found);
        return matched;
    }

    public int getTotalScore(byte[] data) {
        List<String> matches = scan(data);
        int score = 0;
        for (String match : matches) {
            String[] parts = match.split(":");
            if (parts.length == 2) {
                try { score += Integer.parseInt(parts[1]); } catch (Exception ignored) {}
            }
        }
        return score;
    }

    public void addRule(String name, String pattern, int score) {
        addRule(pattern, score);
    }

    private void loadDefaultRules() {
        addRule("windows-update", 40);
        addRule("adobe updater", 35);
        addRule("kms activation", 50);
        addRule("crack", 50);
        addRule("keygen", 50);
        addRule("free bitcoin", 40);
        addRule("gift card generator", 45);
        addRule("steam crack", 55);
        addRule("fortnite aimbot", 55);
        addRule("game hack", 45);
        addRule("loader", 30);
        addRule("reverse shell", 60);
        addRule("/dev/tcp/", 50);
        addRule("Meteoris", 70);
        addRule("meterpreter", 60);
        addRule("-enc", 40);
        addRule("certutil", 35);
        addRule("certutil -urlcache", 45);
        addRule("windowstyle hidden", 35);
        addRule("downloadstring", 35);
        addRule("passwordfox", 60);
        addRule("moz_logins", 45);
        addRule("signons", 40);
        addRule("firefox account", 40);
        addRule("chrome cookies", 45);
        addRule("browser password", 45);
        addRule("saved login", 35);
        addRule("webdata", 35);
        addRule(".sqlite", 30);
        
        addRule("password", 15);
        addRule("logins", 20);
        addRule("encrypted", 15);
        addRule("decrypt", 15);
        addRule("credential", 25);
        addRule("netpass", 30);
        addRule("pwdump", 40);
        addRule("mimikatz", 60);
        addRule("lazagne", 45);
        addRule("pony stealer", 50);
        
        addRule("keylog", 35);
        addRule("keystroke", 30);
        addRule("SetWindowsHookEx", 40);
        addRule("GetAsyncKeyState", 40);
        addRule("WM_KEYDOWN", 35);
        
        addRule("banking", 30);
        addRule("creditcard", 35);
        addRule("cvv", 30);
        addRule("iban", 25);
        addRule("swift code", 30);
        
        addRule("njrat", 60);
        addRule("asyncrat", 55);
        addRule("quasar", 50);
        addRule("remcos", 55);
        addRule("backdoor", 45);
        addRule("trojan", 40);
        addRule("powershell -nop", 45);
        
        addRule("xmrig", 45);
        addRule("cryptonight", 40);
        addRule("stratum", 35);
        
        addRule("ransom", 50);
        addRule("your files", 45);
        addRule("decrypt", 30);
        
        addRule("botnet", 45);
        addRule("ddos", 40);
        addRule("syn flood", 40);
        
        addRule("dropper", 40);
        addRule("downloader", 35);
        addRule("payload", 30);
        addRule("stager", 35);
        addRule("wscript", 35);
        addRule("mshta", 35);
        
        addRule("spyware", 45);
        addRule("screenshot", 30);
        addRule("clipboard", 25);
        addRule("webcam", 35);
        
        addRule("shellcode", 35);
        addRule("virtualalloc", 35);
        addRule("CreateRemoteThread", 40);
        addRule("OpenProcess", 30);
        
        addRule("base64", 20);
        addRule("exec", 15);
        addRule("cmd.exe", 25);
        addRule("powershell.exe", 30);
        addRule("wscript.exe", 30);
        addRule("cscript.exe", 30);
        addRule("mshta.exe", 35);
        
        addRule("http://", 10);
        addRule("https://", 10);
        addRule("connect back", 40);
        
        addRule("admin", 10);
        addRule("root", 15);
        addRule("sudo", 15);
        addRule("su -", 15);

        addRule("coinbase", 35);
        addRule("blockchain", 30);
        addRule("ethereum", 35);
        addRule("bitcoin wallet", 45);
        addRule("wallet.dat", 40);
        addRule("private key", 35);
        addRule("seed phrase", 45);
        addRule("mnemonic", 40);

        addRule("netcat", 40);
        addRule("nc.exe", 35);
        addRule("socat", 35);
        addRule("ncat", 35);
        addRule("skenlogin", 55);
        addRule("xunnel", 50);
        addRule("ssh tunneling", 45);

        addRule("poison ivy", 60);
        addRule("gray", 55);
        addRule("habo", 55);
        addRule("spy", 50);
        addRule("agent", 40);

        addRule("emotet", 70);
        addRule("trickbot", 65);
        addRule("qakbot", 65);
        addRule("icedid", 65);
        addRule("log4j", 60);
        addRule("log4shell", 60);

        addRule("wannacry", 70);
        addRule("petya", 65);
        addRule("notpetya", 65);
        addRule("bad rabbit", 60);

        addRule("azorult", 55);
        addRule("raccoon", 50);
        addRule("videx", 50);
        addRule(" приват", 50);

        addRule("webinject", 45);
        addRule("browser hook", 40);
        addRule("form grabber", 45);
        addRule("cookie stealer", 40);

        addRule("masscan", 40);
        addRule("nmap", 35);
        addRule("zmap", 35);

        addRule("hashcat", 40);
        addRule("john the ripper", 45);
        addRule("hashdump", 40);
        addRule("samdump", 40);

        addRule("lsass", 35);
        addRule("lsass.exe", 40);
        addRule("mimikatz.exe", 55);
        addRule("procdump", 40);
        addRule("memsspect", 50);

        addRule("powershell -ep", 45);
        addRule("iex", 40);
        addRule("invoke-expression", 45);
        addRule("webclient", 35);
        addRule("downloadfile", 35);

        addRule("schtasks", 35);
        addRule("at job", 35);
        addRule("task scheduler", 35);
        addRule("cron", 30);

        addRule("wmi", 35);
        addRule("win32_process", 40);

        addRule("dotnetfx", 30);
        addRule(".net framework", 25);
        addRule("vcredist", 30);

        buildCombinedPattern();
    }

    private void loadUserRules() {
        try {
            String RULES_DIR = System.getProperty("user.home") + "/.antivirus/rules";
            Path dir = Paths.get(RULES_DIR);
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
                return;
            }
            Files.list(dir).filter(p -> p.toString().endsWith(".yar") || p.toString().endsWith(".yara"))
                .forEach(path -> {
                    try {
                        String content = Files.readString(path);
                        parseRuleFile(content);
                    } catch (Exception ignored) {}
                });
        } catch (Exception ignored) {}
    }

    private void parseRuleFile(String content) {
        try {
            String[] lines = content.split("\n");
            String name = null;
            String pattern = null;
            int score = 30;
            
            for (String line : lines) {
                line = line.trim();
                if (line.startsWith("rule ")) {
                    name = line.replace("rule ", "").replace("\"", "").replace("{", "").trim();
                } else if (line.startsWith("$") && line.contains("=\"")) {
                    int start = line.indexOf("=\"") + 2;
                    int end = line.lastIndexOf("\"");
                    if (start > 0 && end > start) {
                        pattern = line.substring(start, end);
                    }
                } else if (line.contains("score:")) {
                    try {
                        score = Integer.parseInt(line.replaceAll("\\D", ""));
                    } catch (Exception ignored) {}
                }
            }
            
            if (name != null && pattern != null) {
                addRule(pattern, score);
            }
        } catch (Exception ignored) {}
    }
}