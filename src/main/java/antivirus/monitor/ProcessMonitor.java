package antivirus.monitor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
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

    public ProcessMonitor(int intervalSeconds) {
        this.scanner = new AntivirusScanner();
        this.scheduler = Executors.newSingleThreadScheduledExecutor();
        this.intervalSeconds = intervalSeconds;
    }

    public void start() {
        running = true;
        System.out.println("[*] Monitor de processos iniciado (intervalo: " + intervalSeconds + "s)");
        
        scheduler.scheduleAtFixedRate(() -> {
            try {
                scanRunningProcesses();
            } catch (Exception e) {
                System.err.println("[!] Erro no scan: " + e.getMessage());
            }
        }, 0, intervalSeconds, TimeUnit.SECONDS);
    }

    public void stop() {
        running = false;
        scheduler.shutdown();
        System.out.println("[*] Monitor parado");
    }

    private void scanRunningProcesses() {
        List<ProcessInfo> processes = getRunningProcesses();
        
        int threatCount = 0;
        for (ProcessInfo pi : processes) {
            try {
                ScanResult result = scanner.scanFile(pi.path, true);
                if (!result.getScore().equals("SEGURO")) {
                    threatCount++;
                    System.out.println("[!] Ameaca detectada: " + pi.name + " (score: " + result.getScore() + ")");
                    if (result.isQuarantined()) {
                        System.out.println("    -> Movido para quarentena");
                    }
                    if (result.isProcessKilled()) {
                        System.out.println("    -> Processo encerrado");
                    }
                }
            } catch (Exception e) {
                // Arquivo pode ter terminado durante a leitura
            }
        }
        
        if (threatCount > 0) {
            System.out.println("[*] Scan completo: " + threatCount + " ameaca(s) encontrada(s)");
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
                        String cmdline = java.nio.file.Files.readString(java.nio.file.Paths.get("/proc/" + pid + "/cmdline"))
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
            System.err.println("[!] Erro ao listar processos: " + e.getMessage());
        }
        
        return processes;
    }

    public static void main(String[] args) {
        int interval = 10;
        if (args.length > 0) {
            try { interval = Integer.parseInt(args[0]); } catch (Exception e) { /* ignore */ }
        }
        
        ProcessMonitor monitor = new ProcessMonitor(interval);
        monitor.start();
        
        System.out.println("Pressione Enter para parar...");
        try {
            System.in.read();
        } catch (Exception e) { /* ignore */ }
        monitor.stop();
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