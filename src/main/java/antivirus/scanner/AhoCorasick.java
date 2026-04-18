package antivirus.scanner;

import java.util.*;

public class AhoCorasick {

    private static final int ALPHABET_SIZE = 256;
    private final Node root = new Node();
    private int nodeCount = 1;

    private static class Node {
        int[] next = new int[ALPHABET_SIZE];
        int link = -1;
        int outputLink = -1;
        List<Integer> patterns = new ArrayList<>();

        Node() {
            Arrays.fill(next, -1);
        }
    }

    public void addPattern(String pattern) {
        int node = 0;
        for (char c : pattern.toCharArray()) {
            int idx = c & 0xFF;
            if (root.next[idx] == -1) {
                root.next[idx] = nodeCount++;
            }
            node = root.next[idx];
        }
        root.patterns.add(node);
    }

    public void build() {
        Queue<Integer> q = new ArrayDeque<>();
        root.link = 0;

        for (int i = 0; i < ALPHABET_SIZE; i++) {
            int child = root.next[i];
            if (child != -1) {
                root.next[child] = root.link;
                q.add(child);
            } else {
                root.next[i] = root.link;
            }
        }

        while (!q.isEmpty()) {
            int v = q.poll();
            root.patterns.add(v);

            for (int i = 0; i < ALPHABET_SIZE; i++) {
                int child = root.next[v];
                if (child != -1) {
                    int link = root.link;
                    while (root.next[link] == -1) {
                        link = root.link;
                    }
                    root.next[child] = root.next[link];
                    q.add(child);
                } else {
                    root.next[v] = root.next[root.link];
                }
            }

            int temp = root.link;
            root.link = root.next[root.link];
            if (root.link == -1) root.link = 0;
            root.link = temp;
        }
    }

    public List<String> search(byte[] data, String[] patternStrings) {
        List<String> found = new ArrayList<>();
        Map<Integer, String> patternMap = new HashMap<>();

        for (int i = 0; i < patternStrings.length; i++) {
            patternMap.put(i, patternStrings[i]);
        }

        int state = 0;
        int limit = Math.min(data.length, 2 * 1024 * 1024);

        for (int i = 0; i < limit; i++) {
            int idx = data[i] & 0xFF;
            if (root.next[state] == -1) {
                state = root.link;
            }
            state = root.next[state];

            int temp = state;
            while (temp != 0) {
                if (root.patterns.contains(temp)) {
                    for (int p : root.patterns) {
                        if (temp == p) {
                            String pat = patternMap.get(p);
                            if (pat != null && !found.contains(pat)) {
                                found.add(pat);
                                if (found.size() >= 10) return found;
                            }
                        }
                    }
                }
                temp = root.link;
                if (temp == 0) break;
            }
        }
        return found;
    }

    public static List<String> searchPatterns(byte[] data, String[] patterns) {
        AhoCorasick ac = new AhoCorasick();
        for (String p : patterns) {
            ac.addPattern(p);
        }
        ac.build();
        return ac.search(data, patterns);
    }
}