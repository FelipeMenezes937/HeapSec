package antivirus.action;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class ProcessKiller {

    public boolean killByPath(String filePath) {
        try {
            String absPath = new java.io.File(filePath).getAbsolutePath();
            List<Integer> pids = findProcessByPath(absPath);
            
            boolean killed = false;
            for (int pid : pids) {
                if (killProcess(pid)) {
                    System.out.println("Processo " + pid + " encerrado");
                    killed = true;
                }
            }
            return killed;
        } catch (Exception e) {
            System.err.println("Erro ao encerrar processo: " + e.getMessage());
            return false;
        }
    }

    private List<Integer> findProcessByPath(String absPath) {
        List<Integer> pids = new ArrayList<>();
        
        try {
            String os = System.getProperty("os.name").toLowerCase();
            
            if (os.contains("windows")) {
                ProcessBuilder pb = new ProcessBuilder("wmic", "process", "where", "name='java.exe'", "get", "ProcessId,ExecutablePath");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains(absPath)) {
                        String[] parts = line.trim().split("\\s+");
                        if (parts.length >= 2) {
                            try {
                                pids.add(Integer.parseInt(parts[0]));
                            } catch (NumberFormatException e) { /* ignore */ }
                        }
                    }
                }
            } else {
                ProcessBuilder pb = new ProcessBuilder("lsof", "-t", absPath);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    try {
                        pids.add(Integer.parseInt(line.trim()));
                    } catch (NumberFormatException e) { /* ignore */ }
                }
            }
            
        } catch (Exception e) {
            System.err.println("Erro ao buscar processo: " + e.getMessage());
        }
        
        return pids;
    }

    private boolean killProcess(int pid) {
        try {
            ProcessBuilder pb;
            if (System.getProperty("os.name").toLowerCase().contains("windows")) {
                pb = new ProcessBuilder("taskkill", "/PID", String.valueOf(pid), "/F");
            } else {
                pb = new ProcessBuilder("kill", "-9", String.valueOf(pid));
            }
            pb.start().waitFor();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}