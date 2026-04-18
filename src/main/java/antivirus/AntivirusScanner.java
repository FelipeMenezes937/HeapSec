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
        return scanFile(filePath, false, false, false);
    }

    public ScanResult scanFile(String filePath, boolean autoAction) throws IOException {
        return scanFile(filePath, autoAction, false, false);
    }

    public ScanResult scanFile(String filePath, boolean autoAction, boolean runSandbox) throws IOException {
        return scanFile(filePath, autoAction, runSandbox, false);
    }

    private static final long MAX_FILE_SIZE = 50 * 1024 * 1024;

    public ScanResult scanFile(String filePath, boolean autoAction, boolean runSandbox, boolean decompress) throws IOException {
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
        String lowerName = fileName.toLowerCase();
        List<String> threats = new ArrayList<>();

        if (decompress && (lowerName.endsWith(".zip") || lowerName.endsWith(".jar"))) {
            logger.info(AntivirusLogger.Category.SCANNER, "Extraindo e analisando: " + filePath);
            ZipExtractor.ExtractResult zr = ZipExtractor.extract(fileData, fileName);
            if (zr.success && zr.tempDir != null) {
                logger.info(AntivirusLogger.Category.SCANNER, "ZIP extraido: " + zr.filesFound + " arquivos");
                threats.add("ZIP extraido: " + zr.filesFound + " arquivos, " + (zr.totalSize / 1024) + "KB");

                try {
                    List<Path> zipFiles = Files.walk(zr.tempDir)
                        .filter(p -> p.toFile().isFile())
                        .limit(50)
                        .toList();

                    for (Path zp : zipFiles) {
                        if (tryScanZipFile(zp.toString())) {
                            threats.add("AMEACA no ZIP: " + zp.getFileName());
                            logger.warn(AntivirusLogger.Category.SCANNER, "AMEACA no ZIP: " + zp);
                        }
                    }
                } catch (Exception e) {
                    logger.info(AntivirusLogger.Category.SCANNER, "Erro ao analisar: " + e.getMessage());
                }

                ZipExtractor.cleanup(zr.tempDir);
            }
        }

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
        threats.addAll(buildThreats(entropy, suspiciousStrings, doubleExtension, peAnalysis, passwordStealerPatterns, category));

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

    private boolean tryScanZipFile(String filePath) {
        try {
            Path path = Path.of(filePath);
            if (!path.toFile().isFile()) return false;

            byte[] data = Files.readAllBytes(path);
            double entropy = entropyAnalyzer.calculateEntropy(data);
            List<String> strings = stringDetector.detect(data);
            boolean doubleExt = extensionChecker.check(path.getFileName().toString());

            int score = 0;
            if (entropy > 7.8) score += 40;
            if (strings.size() >= 2) score += 20;
            if (doubleExt) score += 50;

            return score >= 45;
        } catch (Exception e) {
            return false;
        }
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

    private static final String[] SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/tmp"};
    private static final String[] SKIP_EXT = {".pak", ".map"};
    private static final int PARALLEL_THREADS = Math.max(2, Runtime.getRuntime().availableProcessors() / 2);

    private static final int BATCH_SIZE = 500;

    public List<ScanResult> scanDirectory(String dirPath, boolean autoAction, boolean runSandbox) throws IOException {
        List<ScanResult> results = new ArrayList<>();
        Path basePath = Path.of(dirPath).toAbsolutePath().normalize();

        System.out.println("Contando arquivos...");
        System.out.flush();
        
        long totalFiles = 0;
        try {
            totalFiles = Files.walk(basePath)
                .filter(p -> {
                    try { return p.toFile().isFile() && !shouldSkip(p); }
                    catch (Exception e) { return false; }
                })
                .count();
        } catch (Exception e) {
            System.out.println("Aviso: alguns diretorios nao puderam ser acessados");
        }
        
        int totalBatches = (int) Math.ceil((double) totalFiles / BATCH_SIZE);

        System.out.println("Escaneando " + dirPath + " (" + totalFiles + " arquivos, ~" + totalBatches + " lotes)...");
        System.out.println("(Ctrl+C para parar)");
        System.out.flush();

        int processed = 0;
        int batchNum = 0;

        try {
            java.util.Iterator<Path> it = Files.walk(basePath)
                .filter(p -> p.toFile().isFile())
                .filter(p -> !shouldSkip(p))
                .iterator();

            List<Path> batch = new ArrayList<>(BATCH_SIZE);

            printProgress(0, 0, 0, 0, totalBatches);

            while (it.hasNext()) {
                batch.add(it.next());

                if (batch.size() >= BATCH_SIZE || !it.hasNext()) {
                    List<ScanResult> batchResults = scanBatch(batch, autoAction, runSandbox);
                    results.addAll(batchResults);

                    processed += batch.size();
                    batchNum++;

                    long usedMB = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
                    usedMB /= 1024 * 1024;
                    printProgress(processed, usedMB, results.size(), batchNum, totalBatches);

                    batch.clear();
                    System.gc();
                }
            }
        } catch (Exception e) {
            System.err.println("Escaneamento interrompido: " + e.getMessage());
        }

        System.out.println("\nEscaneamento concluido. " + results.size() + " amenazas encontradas.");
        return results;
    }

    private static void printProgress(int processed, long usedMB, int threats, int batchNum, int totalBatches) {
        String bar = buildProgressBar(batchNum, totalBatches);
        int percent = totalBatches > 0 ? (int) ((batchNum * 100.0) / totalBatches) : 0;
        String line = bar + " " + percent + "% | Arquivos: " + processed + " | Mem: " + usedMB + "MB | Ameacas: " + threats;
        
        String clearLine = "\r" + "                                        " + "\r";
        String output = clearLine + line;
        
        System.out.print(output);
        System.out.flush();
    }

    private static String buildProgressBar(int batchNum, int totalBatches) {
        int total = 20;
        int filled = totalBatches > 0 ? (int) ((batchNum * 20.0) / totalBatches) : 0;
        filled = Math.min(Math.max(filled, 0), total);
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < total; i++) {
            sb.append(i < filled ? "▓" : "░");
        }
        sb.append("]");
        return sb.toString();
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

        if (args.length == 0) {
            runInteractiveMenu(scanner, input);
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

        if (args[0].equals("--daemon")) {
            String watchPath = args.length > 1 ? args[1] : System.getenv("HOME");
            boolean autoQuar = args.length > 2 && args[2].equals("--action");
            System.out.println("Daemon mode: " + watchPath);
            AntivirusScanner sc = new AntivirusScanner();
            startDaemon(sc, watchPath, autoQuar);
            return;
        }

        boolean autoAction = false;
        boolean runSandbox = false;
        boolean decompress = false;

        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--action")) autoAction = true;
            if (args[i].equals("--sandbox")) runSandbox = true;
            if (args[i].equals("-d") || args[i].equals("--decompress")) decompress = true;
        }

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
            ScanResult result = scanner.scanFile(args[0], autoAction, runSandbox, decompress);
            System.out.println(result);
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
            if (!e.getMessage().equals("Interrupted")) {
                System.err.println("Daemon parado: " + e.getMessage());
            }
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

    private static void runInteractiveMenu(AntivirusScanner scanner, Scanner input) {
        while (true) {
            System.out.println("""

                === HeapSec ===
                1. Escanear arquivo
                2. Escanear diretorio
                3. Ver quarentena
                4. Ver logs
                5. Watch logs
                6. Daemon
                7. Ajuda
                8. Sair
                """);
            System.out.print("> ");

            String choice = input.nextLine().trim();

            switch (choice) {
                case "1", "file" -> {
                    System.out.print("Arquivo: ");
                    String f = input.nextLine().trim();
                    if (!f.isEmpty()) {
                        try { System.out.println(scanner.scanFile(f, false, false, false)); } 
                        catch (Exception e) { System.out.println("Erro: " + e.getMessage()); }
                    }
                }
                case "2", "dir" -> {
                    System.out.print("Diretorio [/home/felipe]: ");
                    String d = input.nextLine().trim();
                    if (d.isEmpty()) d = System.getenv("HOME");
                    else if (!d.startsWith("/")) d = System.getenv("HOME") + "/" + d;
                    System.out.println("Escaneando: " + d);
                    try { 
                        var r = scanner.scanDirectory(d, false, false);
                        System.out.println("Total: " + r.size() + " arquivos");
                        int threats = 0;
                        for (var x : r) {
                            if (!x.getScore().equals("SEGURO")) {
                                System.out.println("- " + x.getFileName() + ": " + x.getScore());
                                threats++;
                            }
                        }
                        System.out.println("Ameacas: " + threats);
                    } catch (Exception e) { System.out.println("Erro: " + e.getMessage()); }
                }
                case "3", "q" -> scanner.getQuarantineManager().listQuarantined();
                case "4", "l" -> AntivirusLogger.getInstance().getLogs().forEach(System.out::println);
                case "5", "w" -> watchLogs();
                case "6", "d" -> {
                    System.out.print("Path [/home/felipe]: ");
                    String p = input.nextLine().trim();
                    if (p.isEmpty()) p = System.getenv("HOME");
                    else if (!p.startsWith("/")) p = System.getenv("HOME") + "/" + p;
                    System.out.println("Iniciando daemon: " + p);
                    startDaemon(scanner, p, false);
                }
                case "7", "h" -> System.out.println("Uso: ./heapsec <arq> | ./heapsec -d <arq> | ./heapsec -l | ./heapsec -w");
                case "8", "quit" -> { return; }
                default -> {}
            }
        }
    }
}

