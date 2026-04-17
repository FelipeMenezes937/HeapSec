package antivirus.action;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Gerenciador de quarentena de arquivos suspects.
 * Move arquivos para um diretorio isolado e registra a acao em log.
 */
public class QuarantineManager {

    /** Diretorio onde ficarao os arquivos em quarentena */
    private static final String QUARANTINE_DIR = System.getProperty("user.home") + "/.antivirus/quarantine";

    /**
     * Construtor - cria o diretorio de quarentena se nao existir.
     */
    public QuarantineManager() {
        try {
            Files.createDirectories(Path.of(QUARANTINE_DIR));
        } catch (IOException e) {
            System.err.println("Erro ao criar diretorio de quarentena: " + e.getMessage());
        }
    }

    /**
     * Move um arquivo para a quarentena.
     * O arquivo e renomeado com timestamp para evitar conflitos de nome.
     *
     * @param filePath Caminho do arquivo a ser quarantenado
     * @return true se sucesso, false caso contrario
     */
    public boolean quarantine(String filePath) {
        try {
            Path source = Path.of(filePath);
            if (!Files.exists(source)) {
                System.err.println("Arquivo nao encontrado: " + filePath);
                return false;
            }

            // Gera nome unico com timestamp
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
            String fileName = source.getFileName().toString();
            String quarantinedName = timestamp + "_" + fileName;
            
            Path dest = Path.of(QUARANTINE_DIR, quarantinedName);
            // Move o arquivo para a quarentena
            Files.move(source, dest, StandardCopyOption.REPLACE_EXISTING);
            
            // Registra a acao em log
            logAction(fileName, quarantinedName);
            return true;
        } catch (IOException e) {
            System.err.println("Erro ao mover para quarentena: " + e.getMessage());
            return false;
        }
    }

    /**
     * Registra a acao de quarentena em arquivo de log.
     *
     * @param original Nome original do arquivo
     * @param quarantined Nome do arquivo na quarentena
     */
    private void logAction(String original, String quarantined) {
        try {
            Path logFile = Path.of(QUARANTINE_DIR, "quarantine.log");
            String entry = String.format("[%s] Movido: %s -> %s%n", 
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                original, quarantined);
            Files.writeString(logFile, entry, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Erro ao logar: " + e.getMessage());
        }
    }
    
    /**
     * Lista todos os arquivos currently em quarentena.
     */
    public void listQuarantined() {
        try {
            Path qDir = Path.of(QUARANTINE_DIR);
            if (!Files.exists(qDir)) {
                System.out.println("Sem arquivos em quarentena");
                return;
            }
            var files = Files.list(qDir).filter(p -> !p.getFileName().toString().equals("quarantine.log")).toList();
            if (files.isEmpty()) {
                System.out.println("Sem arquivos em quarentena");
            } else {
                System.out.println("\n=== QUARENTENA ===");
                files.forEach(f -> System.out.println("  - " + f.getFileName()));
            }
        } catch (IOException e) {
            System.out.println("Erro ao listar: " + e.getMessage());
        }
    }
}