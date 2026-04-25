package antivirus.logging;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class AntivirusLogger {

    private static final boolean IS_WINDOWS = System.getProperty("os.name").toLowerCase().contains("windows");
    private static final String LOG_DIR = IS_WINDOWS 
        ? System.getProperty("user.home") + "\\.antivirus\\logs" 
        : System.getProperty("user.home") + "/.antivirus/logs";
    private static final String MAIN_LOG = "antivirus.log";
    private static AntivirusLogger instance;

    public enum Level {
        DEBUG,
        INFO,
        WARN,
        ERROR,
        CRITICAL
    }

    public enum Category {
        SCANNER,
        QUARANTINE,
        SANDBOX,
        PROCESS_MONITOR,
        PROCESS_KILLER,
        SYSTEM
    }

    private AntivirusLogger() {
        try {
            Files.createDirectories(Path.of(LOG_DIR));
        } catch (IOException e) {
            System.err.println("Erro ao criar diretorio de logs: " + e.getMessage());
        }
    }

    public static AntivirusLogger getInstance() {
        if (instance == null) {
            instance = new AntivirusLogger();
        }
        return instance;
    }

    /**
     * Log principal - registra qualquer atividade do antivirus.
     */
    public void log(Level level, Category category, String message) {
        try {
            Path logFile = Path.of(LOG_DIR, MAIN_LOG);
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            String entry = String.format("[%s] [%s] [%s] %s%n", timestamp, level, category, message);

            Files.writeString(logFile, entry,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND);

            // Também imprime no console se for ERROR ou CRITICAL
            if (level == Level.ERROR || level == Level.CRITICAL) {
                System.err.println(entry.trim());
            }
        } catch (IOException e) {
            System.err.println("Erro ao gravar log: " + e.getMessage());
        }
    }

    public void debug(Category category, String message) {
        log(Level.DEBUG, category, message);
    }

    public void info(Category category, String message) {
        log(Level.INFO, category, message);
    }

    public void warn(Category category, String message) {
        log(Level.WARN, category, message);
    }

    public void error(Category category, String message) {
        log(Level.ERROR, category, message);
    }

    public void critical(Category category, String message) {
        log(Level.CRITICAL, category, message);
    }

    /**
     * Log de escaneamento de arquivo.
     */
    public void logScan(String filePath, String score, List<String> threats) {
        String message = String.format("ARQUIVO: %s | SCORE: %s | AMEACAS: %s",
            filePath, score, String.join(", ", threats));
        info(Category.SCANNER, message);
    }

    /**
     * Log de quarentena.
     */
    public void logQuarantine(String filePath, String reason) {
        String message = String.format("ARQUIVO: %s | MOTIVO: %s", filePath, reason);
        info(Category.QUARANTINE, message);
    }

    /**
     * Log de execucao em sandbox.
     */
    public void logSandbox(String filePath, String sandboxType, int exitCode, String behaviors) {
        String message = String.format("ARQUIVO: %s | SANDBOX: %s | EXIT: %d | COMPORTAMENTO: %s",
            filePath, sandboxType, exitCode, behaviors);
        info(Category.SANDBOX, message);
    }

    /**
     * Log de processo killado.
     */
    public void logProcessKilled(int pid, String reason) {
        String message = String.format("PID: %d | MOTIVO: %s", pid, reason);
        warn(Category.PROCESS_KILLER, message);
    }

    /**
     * Retorna todos os logs do antivirus.
     */
    public List<String> getLogs() {
        return getLogs(MAIN_LOG);
    }

    /**
     * Retorna logs de uma sessao especifica.
     */
    public List<String> getSessionLogs(String sessionId) {
        return getLogs("activity_" + sessionId + ".log");
    }

    private List<String> getLogs(String fileName) {
        List<String> lines = new ArrayList<>();
        Path logFile = Path.of(LOG_DIR, fileName);

        if (!Files.exists(logFile)) {
            return lines;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(logFile.toFile()))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
        } catch (IOException e) {
            System.err.println("Erro ao ler logs: " + e.getMessage());
        }

        return lines;
    }

    /**
     * Filtra logs por nivel.
     */
    public List<String> getLogsByLevel(Level level) {
        List<String> filtered = new ArrayList<>();
        for (String line : getLogs()) {
            if (line.contains("[" + level + "]")) {
                filtered.add(line);
            }
        }
        return filtered;
    }

    /**
     * Filtra logs por categoria.
     */
    public List<String> getLogsByCategory(Category category) {
        List<String> filtered = new ArrayList<>();
        for (String line : getLogs()) {
            if (line.contains("[" + category + "]")) {
                filtered.add(line);
            }
        }
        return filtered;
    }

    public String getLogDir() {
        return LOG_DIR;
    }
}