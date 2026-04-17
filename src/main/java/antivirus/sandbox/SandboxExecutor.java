package antivirus.sandbox;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class SandboxExecutor {

    private static final String LOG_DIR = System.getProperty("user.home") + "/.antivirus/logs";
    private SandboxType sandboxType;
    private String sessionId;

    public enum SandboxType {
        FIREJAIL,
        DOCKER,
        GVISOR,
        NATIVE
    }

    public SandboxExecutor() {
        this.sessionId = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        this.sandboxType = detectAvailableSandbox();
        try {
            Files.createDirectories(Path.of(LOG_DIR));
        } catch (IOException e) {
            System.err.println("Erro ao criar diretorio de logs: " + e.getMessage());
        }
    }

    /**
     * Detecta qual sandbox esta disponivel no sistema.
     * Prioridade: firejail > gvisor > docker > native
     */
    private SandboxType detectAvailableSandbox() {
        if (checkCommand("firejail")) {
            return SandboxType.FIREJAIL;
        }
        if (checkCommand("runsc")) {
            return SandboxType.GVISOR;
        }
        if (checkCommand("docker")) {
            return SandboxType.DOCKER;
        }
        return SandboxType.NATIVE;
    }

    private boolean checkCommand(String cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder("which", cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Executa arquivo em sandbox e coleta comportamento.
     *
     * @param filePath Caminho do arquivo a executar
     * @param timeoutSeconds Tempo maximo de execucao
     * @return ExecutionResult com logs e comportamento
     */
    public ExecutionResult execute(String filePath, int timeoutSeconds) {
        Path executable = Path.of(filePath);
        List<String> behaviors = new ArrayList<>();
        String stdout = "";
        String stderr = "";
        int exitCode = -1;

        logActivity("INICIO", "Executando " + filePath + " em sandbox: " + sandboxType);

        try {
            ProcessBuilder pb = buildSandboxProcess(executable);
            pb.redirectErrorStream(true);

            Process process = pb.start();

            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);

            if (finished) {
                exitCode = process.exitValue();
                stdout = readProcessOutput(process.getInputStream());
                logActivity("FIM", "Processo encerrado com codigo: " + exitCode);
            } else {
                process.destroyForcibly();
                behaviors.add("TIMEOUT - processo excedeu limite de tempo");
                logActivity("TIMEOUT", "Processo killed apos " + timeoutSeconds + "s");
            }

            behaviors.addAll(analyzeBehavior(executable));

        } catch (Exception e) {
            behaviors.add("ERRO: " + e.getMessage());
            logActivity("ERRO", e.getMessage());
        }

        return new ExecutionResult(exitCode, stdout, stderr, behaviors);
    }

    private ProcessBuilder buildSandboxProcess(Path executable) {
        ProcessBuilder pb;

        switch (sandboxType) {
            case FIREJAIL:
                pb = new ProcessBuilder("firejail", "--private", "--net=none",
                    "--no-tty", "--quiet", executable.toString());
                break;

            case GVISOR:
                pb = new ProcessBuilder("runsc", "--fs=readonly", "--net=none",
                    "--cpu=none", "--memory=512m", "run", sessionId, executable.toString());
                break;

            case DOCKER:
                pb = new ProcessBuilder("docker", "run", "--rm", "--network=none",
                    "--memory=512m", "--cpus=0.5", "--read-only=true",
                    "-v", executable.getParent() + ":/sandbox:ro",
                    "alpine:latest", "/sandbox/" + executable.getFileName());
                break;

            default:
                pb = new ProcessBuilder(executable.toString());
                pb.environment().clear();
                break;
        }

        return pb;
    }

    private List<String> analyzeBehavior(Path executable) {
        List<String> behaviors = new ArrayList<>();

        behaviors.add("Arquivo: " + executable.getFileName());
        behaviors.add("Tamanho: " + getFileSize(executable) + " bytes");
        behaviors.add("Sandbox: " + sandboxType);

        return behaviors;
    }

    private long getFileSize(Path file) {
        try {
            return Files.size(file);
        } catch (IOException e) {
            return -1;
        }
    }

    private String readProcessOutput(java.io.InputStream is) {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new java.io.InputStreamReader(is))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
        } catch (IOException e) {
            return "Erro ao ler output: " + e.getMessage();
        }
        return sb.toString();
    }

    private void logActivity(String tipo, String mensagem) {
        try {
            Path logFile = Path.of(LOG_DIR, "activity_" + sessionId + ".log");
            String entry = String.format("[%s] [%s] %s%n",
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_TIME),
                tipo, mensagem);
            Files.writeString(logFile, entry,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Erro ao logar atividade: " + e.getMessage());
        }
    }

    public SandboxType getSandboxType() {
        return sandboxType;
    }

    public String getSessionId() {
        return sessionId;
    }

    public static class ExecutionResult {
        public final int exitCode;
        public final String stdout;
        public final String stderr;
        public final List<String> behaviors;

        public ExecutionResult(int exitCode, String stdout, String stderr, List<String> behaviors) {
            this.exitCode = exitCode;
            this.stdout = stdout;
            this.stderr = stderr;
            this.behaviors = behaviors;
        }
    }
}