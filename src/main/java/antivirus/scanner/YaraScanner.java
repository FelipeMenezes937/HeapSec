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
        addRule("windows-update", 50);
        addRule("adobe updater", 45);
        addRule("kms activation", 60);
        addRule("crack", 60);
        addRule("keygen", 60);
        addRule("free bitcoin", 50);
        addRule("gift card generator", 55);
        addRule("steam crack", 65);
        addRule("fortnite aimbot", 65);
        addRule("game hack", 55);
        
        addRule("reverse shell", 70);
        addRule("/dev/tcp/", 60);
        addRule("Meteoris", 80);
        addRule("meterpreter", 70);
        addRule("-enc", 50);
        addRule("certutil -urlcache", 55);
        addRule("windowstyle hidden", 45);
        addRule("downloadstring", 45);
        addRule("passwordfox", 70);
        
        addRule("netpass", 40);
        addRule("pwdump", 50);
        addRule("mimikatz", 70);
        addRule("lazagne", 55);
        addRule("pony stealer", 60);
        
        addRule("SetWindowsHookEx", 50);
        addRule("GetAsyncKeyState", 50);
        
        addRule("creditcard", 55);
        addRule("cvv", 55);
        
        addRule("njrat", 70);
        addRule("asyncrat", 65);
        addRule("quasar", 60);
        addRule("remcos", 65);
        addRule("backdoor", 65);
        addRule("powershell -nop", 55);
        
        addRule("xmrig", 55);
        addRule("ransom", 60);
        
        addRule("botnet", 55);
        addRule("ddos", 50);
        
        addRule("CreateRemoteThread", 55);
        
        addRule("coinbase", 45);
        addRule("bitcoin wallet", 55);
        addRule("wallet.dat", 50);
        addRule("seed phrase", 55);
        
        addRule("netcat", 50);
        addRule("nc.exe", 45);
        addRule("ncat", 45);
        addRule("skenlogin", 65);
        
        addRule("emotet", 80);
        addRule("trickbot", 75);
        addRule("qakbot", 75);
        addRule("log4shell", 70);
        
        addRule("wannacry", 80);
        addRule("petya", 75);
        addRule("notpetya", 75);
        
        addRule("dropper", 55);
        addRule("downloader", 50);
        addRule("payload", 45);
        addRule("stager", 50);
        addRule("wscript", 45);
        addRule("mshta", 45);
        
        addRule("spyware", 55);
        
        addRule("shellcode", 55);
        addRule("virtualalloc", 55);
        addRule("OpenProcess", 50);
        
        addRule("base64", 40);
        addRule("cmd.exe", 45);
        addRule("powershell.exe", 50);
        addRule("wscript.exe", 50);
        addRule("mshta.exe", 55);
        
        addRule("connect back", 60);
        
        addRule("admin", 20);
        addRule("root", 25);
        addRule("sudo", 25);
        addRule("su -", 25);

        addRule("coinbase", 40);
        addRule("blockchain", 35);
        addRule("ethereum", 40);
        addRule("bitcoin wallet", 50);
        addRule("wallet.dat", 45);
        addRule("private key", 40);
        addRule("seed phrase", 50);
        addRule("mnemonic", 45);

        addRule("netcat", 45);
        addRule("nc.exe", 40);
        addRule("socat", 40);
        addRule("ncat", 40);
        addRule("skenlogin", 55);
        addRule("xunnel", 50);
        addRule("ssh tunneling", 50);

        addRule("poison ivy", 60);
        addRule("gray", 55);
        addRule("habo", 55);
        addRule("spy", 60);
        addRule("agent", 50);

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