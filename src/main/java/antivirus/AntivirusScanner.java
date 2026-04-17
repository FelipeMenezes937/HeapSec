package antivirus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import antivirus.action.ProcessKiller;
import antivirus.action.QuarantineManager;
import antivirus.logging.AntivirusLogger;
import antivirus.sandbox.SandboxExecutor;
import antivirus.scanner.EntropyAnalyzer;
import antivirus.scanner.ExtensionChecker;
import antivirus.scanner.PEAnalyzer;
import antivirus.scanner.ScanResult;
import antivirus.scanner.StringDetector;

public class AntivirusScanner {

    private final EntropyAnalyzer entropyAnalyzer;
    private final StringDetector stringDetector;
    private final PEAnalyzer peAnalyzer;
    private final ExtensionChecker extensionChecker;
    private final QuarantineManager quarantineManager;
    private final ProcessKiller processKiller;
    private final AntivirusLogger logger;
    private final SandboxExecutor sandboxExecutor;
    private final boolean sandboxAvailable;

    public AntivirusScanner() {
        this.entropyAnalyzer = new EntropyAnalyzer();
        this.stringDetector = new StringDetector();
        this.peAnalyzer = new PEAnalyzer();
        this.extensionChecker = new ExtensionChecker();
        this.quarantineManager = new QuarantineManager();
        this.processKiller = new ProcessKiller();
        this.logger = AntivirusLogger.getInstance();
        this.sandboxExecutor = new SandboxExecutor();
        this.sandboxAvailable = sandboxExecutor.getSandboxType() != SandboxExecutor.SandboxType.NATIVE;

        this.logger.info(AntivirusLogger.Category.SYSTEM, "Antivirus iniciado");
        if (sandboxAvailable) {
            this.logger.info(AntivirusLogger.Category.SYSTEM,
                "Sandbox disponivel: " + sandboxExecutor.getSandboxType());
        } else {
            this.logger.warn(AntivirusLogger.Category.SYSTEM,
                "Sandbox NAO disponivel - execucao sera feita sem isolamento");
        }
    }

    public QuarantineManager getQuarantineManager() {
        return quarantineManager;
    }

    public ScanResult scanFile(String filePath) throws IOException {
        return scanFile(filePath, false, false);
    }

    public ScanResult scanFile(String filePath, boolean autoAction) throws IOException {
        return scanFile(filePath, autoAction, false);
    }

    public ScanResult scanFile(String filePath, boolean autoAction, boolean runSandbox) throws IOException {
        Path path = Path.of(filePath);
        byte[] fileData = Files.readAllBytes(path);
        String fileName = path.getFileName().toString();

        logger.info(AntivirusLogger.Category.SCANNER, "Iniciando escaneamento: " + filePath);

        double entropy = entropyAnalyzer.calculateEntropy(fileData);
        List<String> suspiciousStrings = stringDetector.detect(fileData);
        List<String> passwordStealerPatterns = stringDetector.detectPasswordStealer(fileData);
        boolean doubleExtension = extensionChecker.check(fileName);
        PEAnalysis peAnalysis = peAnalyzer.analyze(fileData);

        int score = calculateThreatScore(entropy, suspiciousStrings.size(), doubleExtension, peAnalysis, passwordStealerPatterns.size());
        String threatLevel = getThreatLevel(score);
        List<String> threats = buildThreats(entropy, suspiciousStrings, doubleExtension, peAnalysis, passwordStealerPatterns);
        
        boolean quarantined = false;
        boolean processKilled = false;
        boolean sandboxExecuted = false;

        if (runSandbox && sandboxAvailable && score >= 30 && peAnalysis.isValidPE()) {
            logger.info(AntivirusLogger.Category.SANDBOX, "Executando em sandbox: " + filePath);
            SandboxExecutor.ExecutionResult result = sandboxExecutor.execute(filePath, 30);
            threats.add("Sandbox: " + sandboxExecutor.getSandboxType());
            threats.add("Exit code: " + result.exitCode);
            for (String behavior : result.behaviors) {
                threats.add(behavior);
            }
            logger.logSandbox(filePath, sandboxExecutor.getSandboxType().toString(),
                result.exitCode, result.behaviors.toString());
            sandboxExecutor.cleanup();
            sandboxExecuted = true;
        }

        if (autoAction && score >= 10) {
            quarantined = quarantineManager.quarantine(filePath);
            if (quarantined) {
                threats.add("Arquivo movido para quarentena");
                logger.logQuarantine(filePath, "Score: " + score);
            }
            
            if (score >= 80) {
                processKilled = processKiller.killByPath(filePath);
                if (processKilled) {
                    threats.add("Processo encerrado");
                    logger.logProcessKilled(-1, "Score CRITICO: " + score);
                }
            }
        }

        logger.logScan(filePath, threatLevel, threats);

        return new ScanResult(
            fileName,
            fileData.length,
            entropy,
            suspiciousStrings,
            doubleExtension,
            peAnalysis.isValidPE(),
            threatLevel,
            threats,
            quarantined,
            processKilled
        );
    }

    private int calculateThreatScore(double entropy, int suspiciousCount, boolean doubleExt, PEAnalysis peAnalysis, int passwordStealerCount) {
        int score = 0;
        if (entropy > 7.5) score += 40;
        else if (entropy > 6.0) score += 20;
        if (suspiciousCount > 3) score += 30;
        else if (suspiciousCount > 0) score += 10;
        if (doubleExt) score += 50;
        if (peAnalysis.hasPackerSections()) score += 30;
        if (peAnalysis.hasWriteAndExecute()) score += 40;
        
        if (passwordStealerCount >= 5) score += 50;
        else if (passwordStealerCount >= 3) score += 30;
        else if (passwordStealerCount > 0) score += 20;
        
        return score;
    }

    private String getThreatLevel(int score) {
        if (score >= 80) return "CRITICO";
        if (score >= 50) return "ALTO";
        if (score >= 30) return "MEDIO";
        if (score >= 10) return "BAIXO";
        return "SEGURO";
    }

    private List<String> buildThreats(double entropy, List<String> suspicious, boolean doubleExt, PEAnalysis pe, List<String> passwordStealer) {
        List<String> threats = new ArrayList<>();
        if (entropy > 7.5) threats.add(String.format("Alta entropia (%.2f)", entropy));
        else if (entropy > 6.0) threats.add(String.format("Entropia moderada (%.2f)", entropy));
        if (!suspicious.isEmpty()) threats.add("Strings suspeitas: " + String.join(", ", suspicious));
        if (doubleExt) threats.add("Extensao dupla");
        if (pe.hasPackerSections()) threats.add("Secoes de packer detectadas");
        if (pe.hasWriteAndExecute()) threats.add("Secao com Write+Execute");
        if (!passwordStealer.isEmpty()) {
            threats.add("Password stealer: " + String.join(", ", passwordStealer));
        }
        return threats;
    }

    public List<ScanResult> scanDirectory(String dirPath, boolean autoAction) throws IOException {
        return scanDirectory(dirPath, autoAction, false);
    }

    public List<ScanResult> scanDirectory(String dirPath, boolean autoAction, boolean runSandbox) throws IOException {
        List<ScanResult> results = new ArrayList<>();
        Files.walk(Path.of(dirPath))
            .filter(p -> p.toFile().isFile())
            .forEach(p -> {
                try {
                    ScanResult r = scanFile(p.toString(), autoAction, runSandbox);
                    if (!r.getScore().equals("SEGURO")) {
                        results.add(r);
                    }
                } catch (Exception e) {
                    System.err.println("Erro ao escanear " + p + ": " + e.getMessage());
                }
            });
        return results;
    }

    public static void main(String[] args) throws IOException {
        AntivirusScanner scanner = new AntivirusScanner();
        Scanner input = new Scanner(System.in);
        
        if (args.length > 0) {
            boolean autoAction = args.length > 1 && args[1].equals("--action");
            boolean runSandbox = args.length > 2 && args[2].equals("--sandbox");
            ScanResult result = scanner.scanFile(args[0], autoAction, runSandbox);
            System.out.println(result);
            return;
        }
        
        while (true) {
            System.out.println("\n=== ANTIVIRUS LOCAL ===");
            System.out.println("1. Escanear arquivo");
            System.out.println("2. Escanear diretorio");
            System.out.println("3. Ver quarentena");
            System.out.println("4. Ver logs");
            System.out.println("5. Sair");
            System.out.print("> ");
            
            String choice = input.nextLine().trim();
            
            switch (choice) {
                case "1":
                    System.out.print("Caminho do arquivo: ");
                    String filePath = input.nextLine().trim();
                    System.out.print("Acao automatica? (s/n): ");
                    boolean auto = input.nextLine().trim().equalsIgnoreCase("s");
                    System.out.print("Executar em sandbox? (s/n): ");
                    boolean sandbox = input.nextLine().trim().equalsIgnoreCase("s");
                    try {
                        System.out.println(scanner.scanFile(filePath, auto, sandbox));
                    } catch (Exception e) {
                        System.out.println("Erro: " + e.getMessage());
                    }
                    break;
                    
                case "2":
                    System.out.print("Caminho do diretorio: ");
                    String dirPath = input.nextLine().trim();
                    System.out.print("Acao automatica? (s/n): ");
                    boolean autoDir = input.nextLine().trim().equalsIgnoreCase("s");
                    System.out.print("Executar em sandbox? (s/n): ");
                    boolean sandboxDir = input.nextLine().trim().equalsIgnoreCase("s");
                    try {
                        List<ScanResult> results = scanner.scanDirectory(dirPath, autoDir, sandboxDir);
                        for (ScanResult r : results) {
                            System.out.println(r);
                        }
                    } catch (Exception e) {
                        System.out.println("Erro: " + e.getMessage());
                    }
                    break;
                    
case "3":
                    scanner.getQuarantineManager().listQuarantined();
                    break;

                case "4":
                    System.out.println("\n=== LOGS ===");
                    AntivirusLogger.getInstance().getLogs().forEach(System.out::println);
                    break;

                case "5":
                    AntivirusLogger.getInstance().info(AntivirusLogger.Category.SYSTEM, "Antivirus encerrado");
                    System.out.println("Saindo...");
                    return;

                default:
                    System.out.println("Opcao invalida");
            }
        }
    }
}

class PEAnalysis {
    private final boolean validPE;
    private final boolean hasPackerSections;
    private final boolean writeAndExecute;

    public PEAnalysis(boolean validPE, boolean hasPackerSections, boolean writeAndExecute) {
        this.validPE = validPE;
        this.hasPackerSections = hasPackerSections;
        this.writeAndExecute = writeAndExecute;
    }

    public boolean isValidPE() { return validPE; }
    public boolean hasPackerSections() { return hasPackerSections; }
    public boolean hasWriteAndExecute() { return writeAndExecute; }
}