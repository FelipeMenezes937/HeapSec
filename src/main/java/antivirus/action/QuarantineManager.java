package antivirus.action;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.LinkOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import antivirus.security.PathValidator;

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
            Path qDir = Path.of(QUARANTINE_DIR);
            if (Files.exists(qDir)) {
                if (PathValidator.isSymlink(qDir)) {
                    throw new IOException("Diretorio de quarentena e um symlink - seguranca violada");
                }
            } else {
                Files.createDirectories(qDir);
            }
        } catch (IOException e) {
            System.err.println("Erro ao criar diretorio de quarentena: " + e.getMessage());
        }
    }

    private boolean validateSource(Path source) {
        if (!Files.exists(source, LinkOption.NOFOLLOW_LINKS)) {
            System.err.println("Arquivo nao encontrado: " + source);
            return false;
        }

        if (PathValidator.isSymlink(source)) {
            System.err.println("Arquivo e um symlink - ignora por seguranca: " + source);
            return false;
        }

        if (!Files.isRegularFile(source)) {
            System.err.println("Nao e um arquivo regular: " + source);
            return false;
        }

        PathValidator.ValidationResult result = PathValidator.validateFileOperation(source, PathValidator.Operation.DELETE);
        if (!result.valid) {
            System.err.println("Validacao falhou: " + result.error);
            return false;
        }

        return true;
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
            Path source = Path.of(filePath).toAbsolutePath().normalize();

            if (!validateSource(source)) {
                return false;
            }

            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss_SSS"));
            String fileName = source.getFileName().toString();
            String sanitizedName = PathValidator.sanitizePath(fileName);
            String quarantinedName = timestamp + "_" + sanitizedName;

            Path destDir = Path.of(QUARANTINE_DIR);
            if (PathValidator.isSymlink(destDir)) {
                System.err.println("Diretorio de quarentena e symlink!");
                return false;
            }

            Path dest = destDir.resolve(quarantinedName);

            if (Files.exists(dest)) {
                if (PathValidator.isSymlink(dest)) {
                    System.err.println("Destino e symlink!");
                    return false;
                }
                dest = destDir.resolve(timestamp + "_" + System.nanoTime() + "_" + sanitizedName);
            }

            Files.move(source, dest, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);

            logAction(fileName, quarantinedName);
            return true;
        } catch (IOException e) {
            System.err.println("Erro ao mover para quarentena: " + e.getMessage());
            return false;
        }
    }

    public boolean delete(String filePath) {
        try {
            Path source = Path.of(filePath).toAbsolutePath().normalize();
            String fullPath = source.toString();

            String home = System.getProperty("user.home");
            if (fullPath.contains("/antivirus/") || fullPath.contains(home + "/antivirus")) {
                System.err.println("[BLOQUEADO] Tentativa de deletar arquivo do sistema: " + filePath);
                return false;
            }

            if (!validateSource(source)) {
                return false;
            }

            String fileName = source.getFileName().toString();
            Files.delete(source);
            logDelete(fileName);
            return true;
        } catch (IOException e) {
            System.err.println("Erro ao deletar: " + e.getMessage());
            return false;
        }
    }

    private void logDelete(String fileName) {
        try {
            Path logFile = Path.of(QUARANTINE_DIR, "quarantine.log");
            String entry = String.format("[%s] DELETADO: %s%n", 
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                fileName);
            Files.writeString(logFile, entry, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Erro ao logar: " + e.getMessage());
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