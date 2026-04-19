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
        "passwordfox", "browserpass", "netpass",
        "pwdump", "mimikatz", "lazagne", "pony", " credential",
        "moz_logins", "signons", "decrypt",
        "passview", "stealer"
    };

    private static final String[] KEYLOGGER_PATTERNS = {
        "keylog", "keystroke", "SetWindowsHookEx",
        "GetAsyncKeyState", "GetKeyboardState"
    };

    private static final String[] BANKER_PATTERNS = {
        "online banking", "bank transfer", "creditcard", "cvv",
        "card number", "account number", "routing number"
    };

    private static final String[] RAT_PATTERNS = {
        "rat", "remote administration", "backdoor", "trojan", "njrat",
        "njghost", "asyncrat", "quasar", "remcos", "metasploit", "cobalt",
        "tcpconnect", "reverse shell", "connect back"
    };

    private static final String[] CRYPTOMINER_PATTERNS = {
        "cryptonight", "xmrig", "minerd",
        "stratum", "coinhive", "crypto"
    };

    private static final String[] DROPPER_PATTERNS = {
        "dropper", "downloader", "payload", "stager",
        "wscript", "mshta", "bitsadmin"
    };

    private static final String[] SPYWARE_PATTERNS = {
        "spyware", "surveillance", "screenshot",
        "webcam", "microphone"
    };

    private static final String[] BOTNET_PATTERNS = {
        "botnet", "zombie", "ddos",
        "syn flood", "udp flood"
    };

    private static final String[] RANSOMWARE_PATTERNS = {
        "ransom", "your files", "decrypt", "payment",
        "locked files", "all files encrypted"
    };

    private static final int SEARCH_LIMIT = 512 * 1024;
    private static final int MAX_RESULTS = 10;

    private static final AhoCorasickMatcher SUSPICIOUS_MATCHER = new AhoCorasickMatcher(SUSPICIOUS_PATTERNS);
    private static final AhoCorasickMatcher PASSWORD_MATCHER = new AhoCorasickMatcher(PASSWORD_STEALER_PATTERNS);
    private static final AhoCorasickMatcher KEYLOGGER_MATCHER = new AhoCorasickMatcher(KEYLOGGER_PATTERNS);
    private static final AhoCorasickMatcher BANKER_MATCHER = new AhoCorasickMatcher(BANKER_PATTERNS);
    private static final AhoCorasickMatcher RAT_MATCHER = new AhoCorasickMatcher(RAT_PATTERNS);
    private static final AhoCorasickMatcher CRYPTOMINER_MATCHER = new AhoCorasickMatcher(CRYPTOMINER_PATTERNS);
    private static final AhoCorasickMatcher DROPPER_MATCHER = new AhoCorasickMatcher(DROPPER_PATTERNS);
    private static final AhoCorasickMatcher SPYWARE_MATCHER = new AhoCorasickMatcher(SPYWARE_PATTERNS);
    private static final AhoCorasickMatcher BOTNET_MATCHER = new AhoCorasickMatcher(BOTNET_PATTERNS);
    private static final AhoCorasickMatcher RANSOMWARE_MATCHER = new AhoCorasickMatcher(RANSOMWARE_PATTERNS);

    public static List<String> detectSuspicious(byte[] data) {
        byte[] searchData = data.length > SEARCH_LIMIT ? Arrays.copyOf(data, SEARCH_LIMIT) : data;
        return SUSPICIOUS_MATCHER.findMatches(searchData, MAX_RESULTS);
    }

    public static List<String> detectPasswordStealer(byte[] data) {
        byte[] searchData = data.length > SEARCH_LIMIT ? Arrays.copyOf(data, SEARCH_LIMIT) : data;
        return PASSWORD_MATCHER.findMatches(searchData, MAX_RESULTS);
    }

    public static int countPatterns(byte[] data, String[] patterns) {
        byte[] searchData = data.length > SEARCH_LIMIT ? Arrays.copyOf(data, SEARCH_LIMIT) : data;
        AhoCorasickMatcher matcher = new AhoCorasickMatcher(patterns);
        return matcher.countMatches(searchData);
    }

    public static MalwareCategory detectCategory(byte[] data) {
        byte[] searchData = data.length > SEARCH_LIMIT ? Arrays.copyOf(data, SEARCH_LIMIT) : data;

        int psCount = PASSWORD_MATCHER.countMatches(searchData);
        int klCount = KEYLOGGER_MATCHER.countMatches(searchData);
        int bankCount = BANKER_MATCHER.countMatches(searchData);
        int ratCount = RAT_MATCHER.countMatches(searchData);
        int mineCount = CRYPTOMINER_MATCHER.countMatches(searchData);
        int dropCount = DROPPER_MATCHER.countMatches(searchData);
        int spyCount = SPYWARE_MATCHER.countMatches(searchData);
        int botCount = BOTNET_MATCHER.countMatches(searchData);
        int ranCount = RANSOMWARE_MATCHER.countMatches(searchData);

        if (psCount >= 5) return MalwareCategory.PASSWORD_STEALER;
        if (ratCount >= 5) return MalwareCategory.RAT;
        if (ranCount >= 5) return MalwareCategory.RANSOMWARE;
        if (mineCount >= 5) return MalwareCategory.CRYPTOMINER;
        if (bankCount >= 6) return MalwareCategory.BANKER;
        if (klCount >= 5) return MalwareCategory.KEYLOGGER;
        if (dropCount >= 5) return MalwareCategory.DROPPER;
        if (spyCount >= 5) return MalwareCategory.SPYWARE;
        if (botCount >= 5) return MalwareCategory.BOTNET;
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

    private static class AhoCorasickMatcher {
        private final TrieNode root = new TrieNode();
        private final String[] patterns;

        AhoCorasickMatcher(String[] patterns) {
            this.patterns = patterns;
            for (String pattern : patterns) {
                insert(pattern.toLowerCase());
            }
            buildFailureLinks();
        }

        private void insert(String pattern) {
            TrieNode node = root;
            for (char c : pattern.toCharArray()) {
                int idx = c & 0xFF;
                if (node.children[idx] == null) {
                    node.children[idx] = new TrieNode();
                }
                node = node.children[idx];
            }
            node.isEnd = true;
            node.pattern = pattern;
        }

        private void buildFailureLinks() {
            Queue<TrieNode> queue = new LinkedList<>();
            root.fail = root;
            for (int i = 0; i < 256; i++) {
                if (root.children[i] != null) {
                    root.children[i].fail = root;
                    queue.add(root.children[i]);
                } else {
                    root.children[i] = root;
                }
            }
            while (!queue.isEmpty()) {
                TrieNode current = queue.poll();
                for (int i = 0; i < 256; i++) {
                    TrieNode child = current.children[i];
                    if (child != null) {
                        child.fail = current.fail.children[i];
                        queue.add(child);
                    } else {
                        current.children[i] = current.fail.children[i];
                    }
                }
            }
        }

        private static class TrieNode {
            TrieNode[] children = new TrieNode[256];
            TrieNode fail;
            boolean isEnd;
            String pattern;
        }

        List<String> findMatches(byte[] data, int maxMatches) {
            List<String> found = new ArrayList<>();
            TrieNode state = root;

            for (int i = 0; i < data.length && found.size() < maxMatches; i++) {
                int b = data[i] & 0xFF;
                if (b >= 'A' && b <= 'Z') b = b + 32;
                state = state.children[b];

                if (state == null) {
                    state = root;
                    continue;
                }

                TrieNode temp = state;
                while (temp != root) {
                    if (temp.isEnd && !found.contains(temp.pattern)) {
                        found.add(temp.pattern);
                        if (found.size() >= maxMatches) break;
                    }
                    temp = temp.fail;
                }
            }
            return found;
        }

        int countMatches(byte[] data) {
            Set<String> found = new HashSet<>();
            TrieNode state = root;

            for (int i = 0; i < data.length; i++) {
                int b = data[i] & 0xFF;
                if (b >= 'A' && b <= 'Z') b = b + 32;
                state = state.children[b];

                if (state == null) {
                    state = root;
                    continue;
                }

                TrieNode temp = state;
                while (temp != root) {
                    if (temp.isEnd) {
                        found.add(temp.pattern);
                    }
                    temp = temp.fail;
                }
            }
            return found.size();
        }
    }
}