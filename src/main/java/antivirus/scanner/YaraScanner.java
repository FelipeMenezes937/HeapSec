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
        return getTotalScore(data, 0);
    }

    public int getTotalScore(byte[] data, int minThreshold) {
        List<String> matches = scan(data);
        int score = 0;
        for (String match : matches) {
            String[] parts = match.split(":");
            if (parts.length == 2) {
                try {
                    int ruleScore = Integer.parseInt(parts[1]);
                    if (ruleScore >= minThreshold) {
                        score += ruleScore;
                    }
                } catch (Exception ignored) {}
            }
        }
        return score;
    }

    public void addRule(String name, String pattern, int score) {
        addRule(pattern, score);
    }

    private void loadDefaultRules() {
        addRule("kms activation", 60);
        addRule("kmspico", 70);
        addRule("crack", 50);
        addRule("keygen", 55);
        addRule("free bitcoin", 45);
        addRule("steam crack", 60);
        addRule("fortnite aimbot", 60);
        addRule("game hack", 50);

        addRule("reverse shell", 70);
        addRule("Meteoris", 80);
        addRule("meterpreter", 65);
        addRule("certutil -urlcache", 55);
        addRule("windowstyle hidden", 45);
        addRule("downloadstring", 40);
        addRule("passwordfox", 65);

        addRule("netpass", 40);
        addRule("pwdump", 50);
        addRule("mimikatz", 65);
        addRule("lazagne", 55);
        addRule("pony stealer", 60);

        addRule("SetWindowsHookEx", 45);
        addRule("GetAsyncKeyState", 45);

        addRule("creditcard", 45);
        addRule("cvv", 40);

        addRule("njrat", 70);
        addRule("asyncrat", 65);
        addRule("quasar", 60);
        addRule("remcos", 65);
        addRule("backdoor", 55);
        addRule("powershell -nop", 50);

        addRule("xmrig", 55);
        addRule("ransom", 55);

        addRule("botnet", 50);
        addRule("ddos", 45);

        addRule("CreateRemoteThread", 50);

        addRule("coinbase", 35);
        addRule("bitcoin wallet", 45);
        addRule("wallet.dat", 50);
        addRule("seed phrase", 50);

        addRule("netcat", 35);
        addRule("nc.exe", 40);
        addRule("ncat", 35);
        addRule("skenlogin", 60);
        addRule("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", 100);

        addRule("emotet", 80);
        addRule("trickbot", 75);
        addRule("qakbot", 75);
        addRule("log4shell", 70);

        addRule("wannacry", 80);
        addRule("petya", 75);
        addRule("notpetya", 75);

        addRule("dropper", 45);
        addRule("downloader", 40);
        addRule("payload", 40);
        addRule("stager", 45);
        addRule("wscript", 40);
        addRule("mshta", 40);

        addRule("spyware", 50);

        addRule("shellcode", 50);
        addRule("virtualalloc", 45);
        addRule("OpenProcess", 45);

        addRule("cmd.exe", 35);
        addRule("powershell.exe", 40);
        addRule("wscript.exe", 45);
        addRule("mshta.exe", 50);

        addRule("connect back", 55);

        addRule("coinbase", 30);
        addRule("blockchain", 25);
        addRule("ethereum", 30);
        addRule("private key", 30);
        addRule("mnemonic", 35);

        addRule("socat", 35);
        addRule("xunnel", 45);
        addRule("ssh tunneling", 40);

        addRule("poison ivy", 60);
        addRule("gray", 40);
        addRule("habo", 40);
        addRule("spy", 45);
        addRule("agent", 35);

        addRule("emotet", 70);
        addRule("trickbot", 65);
        addRule("qakbot", 65);
        addRule("icedid", 65);
        addRule("log4j", 55);
        addRule("log4shell", 60);

        addRule("wannacry", 70);
        addRule("petya", 65);
        addRule("notpetya", 65);
        addRule("bad rabbit", 60);

        addRule("azorult", 55);
        addRule("raccoon", 50);
        addRule("videx", 50);
        addRule(" privat", 45);

        addRule("webinject", 40);
        addRule("browser hook", 35);
        addRule("form grabber", 40);
        addRule("cookie stealer", 35);

        addRule("masscan", 35);
        addRule("nmap", 25);
        addRule("zmap", 25);

        addRule("hashcat", 35);
        addRule("john the ripper", 40);
        addRule("hashdump", 40);
        addRule("samdump", 40);

        addRule("lsass", 30);
        addRule("lsass.exe", 35);
        addRule("mimikatz.exe", 50);
        addRule("procdump", 35);
        addRule("memsspect", 45);

        addRule("powershell -ep", 40);
        addRule("iex", 35);
        addRule("invoke-expression", 40);
        addRule("webclient", 30);
        addRule("downloadfile", 30);

        addRule("schtasks", 30);
        addRule("task scheduler", 25);
        addRule("wmi", 30);
        addRule("win32_process", 35);

        addRule("/dev/tcp/", 50);
        addRule("-enc", 35);
        addRule("base64", 20);

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