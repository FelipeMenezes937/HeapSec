package antivirus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ForkJoinPool;

import antivirus.action.ProcessKiller;
import antivirus.action.QuarantineManager;
import antivirus.logging.AntivirusLogger;
import antivirus.sandbox.SandboxExecutor;
import antivirus.scanner.EntropyAnalyzer;
import antivirus.scanner.ExtensionChecker;
import antivirus.scanner.HashCache;
import antivirus.scanner.PEAnalyzer;
import antivirus.scanner.PEAnalysis;
import antivirus.scanner.ScanResult;
import antivirus.scanner.StringDetector;
import antivirus.scanner.ZipExtractor;

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
        HashCache.init();
        this.logger.info(AntivirusLogger.Category.SYSTEM, "Cache carregado: " + HashCache.size() + " entradas");

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

    private static final long MAX_FILE_SIZE = 50 * 1024 * 1024;

    public ScanResult scanFile(String filePath, boolean autoAction, boolean runSandbox) throws IOException {
        Path path = Path.of(filePath);

        if (HashCache.isCached(path)) {
            long fileSize = Files.size(path);
            String cachedResult = HashCache.getCachedResult(path);
            logger.info(AntivirusLogger.Category.SCANNER, "Cache hit: " + filePath);
            return new ScanResult(
                path.getFileName().toString(),
                fileSize,
                0,
                List.of(),
                false,
                false,
                cachedResult,
                List.of("Resultado em cache"),
                false,
                false
            );
        }

        long fileSize;
        try {
            if (Files.isDirectory(path)) {
                List<ScanResult> results = scanDirectory(path.toString(), false, false);
                return new ScanResult(
                    path.getFileName().toString(),
                    0,
                    0,
                    List.of(),
                    false,
                    false,
                    "DIRETORIO",
                    List.of("Escaneado " + results.size() + " arquivos"),
                    false,
                    false
                );
            }
            fileSize = Files.size(path);
        } catch (Exception e) {
            return new ScanResult(
                path.getFileName().toString(),
                0,
                0,
                List.of(),
                false,
                false,
                "SEGURO",
                List.of("Erro ao ler: " + e.getMessage()),
                false,
                false
            );
        }

        if (fileSize > MAX_FILE_SIZE) {
            return new ScanResult(
                path.getFileName().toString(),
                fileSize,
                0,
                List.of(),
                false,
                false,
                "SEGURO",
                List.of("Arquivo muito grande (" + (fileSize / 1024 / 1024) + "MB) - ignorado"),
                false,
                false
            );
        }

        byte[] fileData = Files.readAllBytes(path);
        String fileName = path.getFileName().toString();

        logger.info(AntivirusLogger.Category.SCANNER, "Iniciando escaneamento: " + filePath);

        double entropy = entropyAnalyzer.calculateEntropy(fileData);
        List<String> suspiciousStrings = stringDetector.detect(fileData);
        List<String> passwordStealerPatterns = stringDetector.detectPasswordStealer(fileData);
        StringDetector.MalwareCategory category = stringDetector.detectCategory(fileData);
        int categoryScore = stringDetector.getCategoryScore(fileData);
        boolean doubleExtension = extensionChecker.check(fileName);
        PEAnalysis peAnalysis = peAnalyzer.analyze(fileData);

        int score = calculateThreatScore(entropy, suspiciousStrings.size(), doubleExtension, peAnalysis, passwordStealerPatterns.size());
        
        if (categoryScore > 0) {
            score += categoryScore;
        }
        
        String threatLevel = getThreatLevel(score);
        List<String> threats = buildThreats(entropy, suspiciousStrings, doubleExtension, peAnalysis, passwordStealerPatterns, category);
        
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

        if (autoAction && score >= 30) {
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
        HashCache.put(path, threatLevel);
        HashCache.save();

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
        if (entropy > 7.8) score += 40;
        else if (entropy > 7.2) score += 15;
        if (suspiciousCount > 3) score += 30;
        else if (suspiciousCount > 5) score += 10;
        if (doubleExt) score += 40;
        if (peAnalysis.hasPackerSections()) score += 25;
        if (peAnalysis.hasWriteAndExecute()) score += 35;

        if (passwordStealerCount >= 5) score += 40;
        else if (passwordStealerCount >= 3) score += 20;

        return score;
    }

    private String getThreatLevel(int score) {
        if (score >= 100) return "CRITICO";
        if (score >= 70) return "ALTO";
        if (score >= 45) return "MEDIO";
        if (score >= 25) return "BAIXO";
        return "SEGURO";
    }

    private List<String> buildThreats(double entropy, List<String> suspicious, boolean doubleExt, PEAnalysis pe, List<String> passwordStealer, StringDetector.MalwareCategory category) {
        List<String> threats = new ArrayList<>();
        if (entropy > 7.8) threats.add(String.format("Alta entropia (%.2f)", entropy));
        else if (entropy > 7.2) threats.add(String.format("Entropia elevada (%.2f)", entropy));
        if (suspicious.size() > 3) threats.add("Strings suspeitas: " + String.join(", ", suspicious));
        if (doubleExt) threats.add("Extensao dupla");
        if (pe.hasPackerSections()) threats.add("Secoes de packer detectadas");
        if (pe.hasWriteAndExecute()) threats.add("Secao com Write+Execute");
        if (passwordStealer.size() >= 3) {
            threats.add("Password stealer: " + String.join(", ", passwordStealer));
        }
        if (category != StringDetector.MalwareCategory.UNKNOWN && category != StringDetector.MalwareCategory.SUSPICIOUS) {
            threats.add("Categoria: " + category);
        }
        return threats;
    }

    public List<ScanResult> scanDirectory(String dirPath, boolean autoAction) throws IOException {
        return scanDirectory(dirPath, autoAction, false);
    }

    private static final String[] SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/tmp", ".cache", "node_modules", ".npm", ".gradle", "vendor", "bin/lib", "modules", ".local", "wokwi"};
    private static final String[] SKIP_EXT = {".pak", ".dat", ".idx", ".db", ".sqlite", ".map", ".bin", ".elf"};
    private static final int PARALLEL_THREADS = Math.max(2, Runtime.getRuntime().availableProcessors() / 2);

    private static final int BATCH_SIZE = 500;

    public List<ScanResult> scanDirectory(String dirPath, boolean autoAction, boolean runSandbox) throws IOException {
        List<ScanResult> results = new ArrayList<>();
        Path basePath = Path.of(dirPath).toAbsolutePath().normalize();

        System.out.println("Escaneando " + dirPath + " em lotes de " + BATCH_SIZE + "...");
        System.out.println("(Ctrl+C para parar)");

        int processed = 0;
        int batchNum = 0;

        try {
            java.util.Iterator<Path> it = Files.walk(basePath)
                .filter(p -> p.toFile().isFile())
                .filter(p -> !shouldSkip(p))
                .iterator();

            List<Path> batch = new ArrayList<>(BATCH_SIZE);

            while (it.hasNext()) {
                batch.add(it.next());

                if (batch.size() >= BATCH_SIZE || !it.hasNext()) {
                    List<ScanResult> batchResults = scanBatch(batch, autoAction, runSandbox);
                    results.addAll(batchResults);

                    processed += batch.size();
                    batchNum++;

                    long usedMB = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
                    usedMB /= 1024 * 1024;
                    System.out.println("[" + batchNum + "] " + processed + " arquivos | Mem: " + usedMB + "MB | Ameacas: " + results.size());

                    batch.clear();
                    System.gc();
                }
            }
        } catch (Exception e) {
            System.err.println("Escaneamento interrompido: " + e.getMessage());
        }

        System.out.println("Escaneamento concluido. " + results.size() + " amenazas encontradas.");
        return results;
    }

    private List<ScanResult> scanBatch(List<Path> files, boolean autoAction, boolean runSandbox) {
        List<ScanResult> batchResults = new ArrayList<>();
        ForkJoinPool pool = new ForkJoinPool(PARALLEL_THREADS);
        try {
            pool.submit(() -> files.parallelStream().forEach(p -> {
                try {
                    ScanResult r = scanFile(p.toString(), autoAction, runSandbox);
                    if (!r.getScore().equals("SEGURO")) {
                        synchronized (batchResults) {
                            batchResults.add(r);
                        }
                    }
                } catch (Exception e) {
                    // silent
                }
            })).get();
        } catch (Exception e) {
            // silent
        } finally {
            pool.shutdown();
        }
        return batchResults;
    }

    private boolean shouldSkip(Path path) {
        String pathStr = path.toString();
        String lower = pathStr.toLowerCase();
        for (String skip : SKIP_DIRS) {
            if (lower.contains(skip.toLowerCase())) {
                return true;
            }
        }
        String fileName = path.getFileName().toString().toLowerCase();
        for (String ext : SKIP_EXT) {
            if (fileName.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    public static void main(String[] args) throws IOException {
        AntivirusScanner scanner = new AntivirusScanner();
        AntivirusLogger logger = AntivirusLogger.getInstance();
        Scanner input = new Scanner(System.in);
        
        if (args.length > 0) {
            if (args[0].equals("--daemon")) {
                String watchPath = args.length > 1 ? args[1] : System.getenv("HOME");
                boolean autoQuar = args.length > 2 && args[2].equals("--action");
                System.out.println("Daemon mode: " + watchPath);
                AntivirusScanner sc = new AntivirusScanner();
                startDaemon(sc, watchPath, autoQuar);
                return;
            }

            if (args[0].equals("-l") || args[0].equals("--logs")) {
                System.out.println("\n=== LOGS DO ANTIVIRUS ===");
                logger.getLogs().forEach(System.out::println);
                return;
            }
            
            if (args[0].equals("-w") || args[0].equals("--watch")) {
                watchLogs();
                return;
            }
            boolean autoAction = args.length > 1 && args[1].equals("--action");
            boolean runSandbox = args.length > 2 && args[2].equals("--sandbox");
            Path path = Path.of(args[0]);

            if (Files.isDirectory(path)) {
                List<ScanResult> results = scanner.scanDirectory(args[0], autoAction, runSandbox);
                System.out.println("\n=== RESULTADO DO ESCANEAMENTO ===");
                System.out.println("Total de amenazas: " + results.size());
                for (ScanResult r : results) {
                    System.out.println(r);
                    System.out.println("---");
                }
            } else {
                ScanResult result = scanner.scanFile(args[0], autoAction, runSandbox);
                System.out.println(result);
            }
            return;
        }
        
        while (true) {
            System.out.println("""

                === ANTIVIRUS LOCAL ===
                1. Escanear arquivo
                2. Escanear diretorio
                3. Ver quarentena
                4. Ver logs
                5. Watch logs (tempo real)
                6. Modo daemon (monitoramento)
                7. Ajuda
                8. Sair
                """);
            System.out.print("> ");

            String choice = input.nextLine().trim();

            switch (choice) {
                case "1", "arquivo", "file" -> {
                    System.out.print("Caminho do arquivo: ");
                    String filePath = input.nextLine().trim();
                    if (filePath.isEmpty()) break;
                    System.out.print("Quarentena automatica? (s/N): ");
                    boolean auto = input.nextLine().trim().equalsIgnoreCase("s");
                    try {
                        System.out.println(scanner.scanFile(filePath, auto, false));
                    } catch (Exception e) {
                        System.out.println("Erro: " + e.getMessage());
                    }
                }

                case "2", "diretorio", "dir" -> {
                    System.out.print("Caminho do diretorio [Enter=/home/felipe]: ");
                    String dirPath = input.nextLine().trim();
                    if (dirPath.isEmpty()) dirPath = System.getenv("HOME");
                    System.out.print("Quarentena automatica? (s/N): ");
                    boolean auto = input.nextLine().trim().equalsIgnoreCase("s");
                    System.out.println("[Enter] para iniciar...");
                    input.nextLine();
                    try {
                        List<ScanResult> results = scanner.scanDirectory(dirPath, auto, false);
                        System.out.println("\n===RESULTADO===");
                        System.out.println("Totais: " + results.size());
                        results.forEach(r -> System.out.println("- " + r.getFileName() + ": " + r.getScore()));
                    } catch (Exception e) {
                        System.out.println("Erro: " + e.getMessage());
                    }
                }

                case "3", "quarentena" -> scanner.getQuarantineManager().listQuarantined();

                case "4", "logs", "l" -> {
                    System.out.println("\n=== ULTIMOS LOGS ===");
                    var logs = AntivirusLogger.getInstance().getLogs();
                    logs.stream().skip(Math.max(0, logs.size() - 20)).forEach(System.out::println);
                }

                case "5", "watch", "w" -> watchLogs();

                case "6", "daemon", "d" -> {
                    System.out.print("Diretorio para monitorar [Enter=/home/felipe]: ");
                    String watchPath = input.nextLine().trim();
                    if (watchPath.isEmpty()) watchPath = System.getenv("HOME");
                    System.out.print("Quarentena automatica? (s/N): ");
                    boolean auto = input.nextLine().trim().equalsIgnoreCase("s");
                    System.out.println("Iniciando daemon...");
                    System.out.println("Monitorando: " + watchPath);
                    System.out.println("Pressione Ctrl+C para parar");
                    startDaemon(scanner, watchPath, auto);
                }

                case "7", "ajuda", "help", "h" -> System.out.println("""
                    USO:
                      antivirus arquivo.exe         - escanear arquivo
                      antivirus /pasta           - escanear diretorio
                      antivirus arquivo.exe --action - escanear + quarentenar
                      antivirus -l                 - ver logs
                      antivirus -w                 - watch logs

                    MENU:
                      1 - scan arquivo
                      2 - scan diretorio (lote)
                      3 - ver quarentena
                      4 - ver ultimos 20 logs
                      5 - watch logs tempo real
                      6 - modo daemon (monitoramento)
                      8 - sair
                    """);

                case "8", "sair", "exit", "quit" -> {
                    AntivirusLogger.getInstance().info(AntivirusLogger.Category.SYSTEM, "Antivirus encerrado");
                    System.out.println("Saindo...");
                    return;
                }

                default -> System.out.println("Opcao invalida. Digite 7 para ajuda.");
            }
        }
    }

    private static void startDaemon(AntivirusScanner scanner, String watchPath, boolean autoQuarantine) {
        AntivirusLogger logger = AntivirusLogger.getInstance();
        logger.info(AntivirusLogger.Category.SYSTEM, "Daemon iniciado em: " + watchPath);

        try (java.nio.file.WatchService watchService = java.nio.file.FileSystems.getDefault().newWatchService()) {
            Path path = Path.of(watchPath);
            path.register(watchService,
                java.nio.file.StandardWatchEventKinds.ENTRY_CREATE,
                java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY);

            System.out.println("Daemon ativo! Monitorando alteracoes...");

            while (true) {
                WatchKey key = watchService.take();
                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent<Path> ev = (WatchEvent<Path>) event;
                    Path filename = ev.context();
                    Path fullPath = path.resolve(filename);

                    if (Files.isRegularFile(fullPath)) {
                        String ext = filename.toString().toLowerCase();
                        if (ext.endsWith(".exe") || ext.endsWith(".sh") || ext.endsWith(".bat") ||
                            ext.endsWith(".ps1") || ext.endsWith(".vbs") || ext.endsWith(".js")) {

                            System.out.println("[DAEMON] Novo arquivo detectado: " + filename);
                            try {
                                ScanResult result = scanner.scanFile(fullPath.toString(), autoQuarantine, false);
                                if (!result.getScore().equals("SEGURO")) {
                                    System.out.println("[ALERTA] " + result.getFileName() + " -> " + result.getScore());
                                }
                            } catch (Exception e) {
                                System.err.println("Erro ao escanear: " + e.getMessage());
                            }
                        }
                    }
                }
                key.reset();
            }
        } catch (Exception e) {
            System.err.println("Daemon parado: " + e.getMessage());
        }
    }

    private static void watchLogs() {
        AntivirusLogger logger = AntivirusLogger.getInstance();
        int lastCount = 0;
        
        System.out.println("\n=== WATCH LOGS (Ctrl+C para sair) ===");
        System.out.println("Aguardando novas entradas...\n");
        
        while (true) {
            try {
                List<String> logs = logger.getLogs();
                if (logs.size() > lastCount) {
                    System.out.print("\033[H\033[2J");
                    System.out.println("\n=== ANTIVIRUS LOGS (ao vivo) ===\n");
                    for (int i = Math.max(0, logs.size() - 20); i < logs.size(); i++) {
                        System.out.println(logs.get(i));
                    }
                    System.out.println("\nAguardando...");
                    lastCount = logs.size();
                }
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                System.out.println("\nParado.");
                break;
            }
        }
    }
}

