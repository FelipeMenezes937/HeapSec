package antivirus.monitor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import antivirus.AntivirusScanner;
import antivirus.scanner.ScanResult;

public class ProcessMonitor {

    private final AntivirusScanner scanner;
    private final ScheduledExecutorService scheduler;
    private boolean running = false;
    private final int intervalSeconds;
    private boolean decompress = false;
    private boolean autoQuarantine = false;
    private String watchPath = null;

    public ProcessMonitor(int intervalSeconds) {
        this(intervalSeconds, false, false, null);
    }

    public ProcessMonitor(int intervalSeconds, boolean decompress, boolean autoQuarantine, String watchPath) {
        this.scanner = new AntivirusScanner();
        this.scheduler = Executors.newSingleThreadScheduledExecutor();
        this.intervalSeconds = intervalSeconds;
        this.decompress = decompress;
        this.autoQuarantine = autoQuarantine;
        this.watchPath = watchPath;
    }

    public void start() {
        running = true;
        System.out.println("[*] Monitor HeapSec iniciado (intervalo: " + intervalSeconds + "s)");
        System.out.println("    Decompress: " + decompress + " | Auto-quarentena: " + autoQuarantine);

        if (watchPath != null) {
            System.out.println("    Modo varredura: " + watchPath);
            scanDirectory();
        } else {
            System.out.println("    Modo processos");
            scheduler.scheduleAtFixedRate(() -> {
                try {
                    scanRunningProcesses();
                } catch (Exception e) {
                    System.err.println("[!] Erro no scan: " + e.getMessage());
                }
            }, 0, intervalSeconds, TimeUnit.SECONDS);
        }
    }

    public void stop() {
        running = false;
        scheduler.shutdown();
        System.out.println("[*] Monitor parado");
    }

    private void scanDirectory() {
        try {
            List<ScanResult> results = scanner.scanDirectory(watchPath, autoQuarantine, decompress);
            int threats = 0;
            for (ScanResult r : results) {
                if (!r.getScore().equals("SEGURO")) {
                    threats++;
                    System.out.println("[!] " + r.getFileName() + " -> " + r.getScore());
                }
            }
            System.out.println("[*] Varredura completa: " + threats + " ameacas de " + results.size() + " arquivos");
        } catch (Exception e) {
            System.err.println("[!] Erro: " + e.getMessage());
        }
    }

    private void scanRunningProcesses() {
        List<ProcessInfo> processes = getRunningProcesses();

        int threatCount = 0;
        for (ProcessInfo pi : processes) {
            try {
                ScanResult result = scanner.scanFile(pi.path, autoQuarantine, false, decompress);
                if (!result.getScore().equals("SEGURO")) {
                    threatCount++;
                    System.out.println("[!] " + pi.name + " -> " + result.getScore());
                    if (result.isQuarantined()) {
                        System.out.println("    -> Quarentena");
                    }
                }
            } catch (Exception e) {
                // pode ter terminado
            }
        }

        if (threatCount > 0) {
            System.out.println("[*] Scan: " + threatCount + " ameaca(s)");
        }
    }

    private List<ProcessInfo> getRunningProcesses() {
        List<ProcessInfo> processes = new ArrayList<>();

        try {
            String os = System.getProperty("os.name").toLowerCase();

            if (os.contains("windows")) {
                ProcessBuilder pb = new ProcessBuilder("wmic", "process", "get", "ProcessId,ExecutablePath");
                pb.redirectErrorStream(true);
                Process p = pb.start();

                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                boolean first = true;
                while ((line = reader.readLine()) != null) {
                    if (first) { first = false; continue; }
                    line = line.trim();
                    if (line.isEmpty()) continue;

                    String[] parts = line.split("\\s+", 2);
                    if (parts.length >= 2) {
                        try {
                            int pid = Integer.parseInt(parts[0]);
                            String path = parts[1];
                            if (!path.isEmpty() && !path.equals("N/A")) {
                                processes.add(new ProcessInfo(pid, path));
                            }
                        } catch (NumberFormatException e) { /* ignore */ }
                    }
                }
            } else {
                java.io.File proc = new java.io.File("/proc");
                for (java.io.File f : proc.listFiles()) {
                    try {
                        int pid = Integer.parseInt(f.getName());
                        String cmdline = Files.readString(Path.of("/proc/" + pid + "/cmdline"))
                            .replace('\0', ' ').trim();
                        if (!cmdline.isEmpty()) {
                            String[] parts = cmdline.split("\\s+");
                            if (parts.length > 0) {
                                processes.add(new ProcessInfo(pid, parts[0]));
                            }
                        }
                    } catch (Exception e) { /* ignore */ }
                }
            }
        } catch (Exception e) {
            System.err.println("[!] Erro: " + e.getMessage());
        }

        return processes;
    }

    public static void main(String[] args) {
        int interval = 10;
        boolean decompress = false;
        boolean autoQuar = false;
        String path = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-d", "--decompress" -> decompress = true;
                case "-q", "--quarantine" -> autoQuar = true;
                case "-t" -> {
                    if (i + 1 < args.length) {
                        try { interval = Integer.parseInt(args[i + 1]); } catch (Exception e) { }
                    }
                }
                default -> {
                    if (!args[i].startsWith("-") && Files.isDirectory(Path.of(args[i]))) {
                        path = args[i];
                    }
                }
            }
        }

        System.out.println("""
            HeapSec Monitor
            ===============
            -t <seg>    Intervalo (padrao: 10)
            -d          Extrair e analisar ZIPs
            -q          Quarentena automatica
            <path>     Escaneia diretorio (modo unico)
            """);

        ProcessMonitor monitor = new ProcessMonitor(interval, decompress, autoQuar, path);
        monitor.start();

        if (path == null) {
            System.out.println("Pressione Enter para parar...");
            try { System.in.read(); } catch (Exception e) { }
            monitor.stop();
        }
    }

    private static class ProcessInfo {
        final int pid;
        final String path;
        final String name;

        ProcessInfo(int pid, String path) {
            this.pid = pid;
            this.path = path;
            this.name = new java.io.File(path).getName();
        }
    }
}