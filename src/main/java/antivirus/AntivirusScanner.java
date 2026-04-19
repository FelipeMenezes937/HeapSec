package antivirus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.Collections;
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
import antivirus.scanner.BoyerMooreStringDetector;
import antivirus.scanner.DirectoryCache;
import antivirus.scanner.YaraScanner;
import antivirus.scanner.ZipExtractor;
import antivirus.security.PathValidator;

public class AntivirusScanner {

    private final EntropyAnalyzer entropyAnalyzer;
    private final PEAnalyzer peAnalyzer;
    private final ExtensionChecker extensionChecker;
    private final QuarantineManager quarantineManager;
    private final ProcessKiller processKiller;
    private final AntivirusLogger logger;
    private final SandboxExecutor sandboxExecutor;
    private final YaraScanner yaraScanner;
    private final boolean sandboxAvailable;
    private boolean autoDelete = true;

    private static String[] PROTECTED_PREFIXES = null;

    private static int totalScanned = 0;
    private static int totalDeleted = 0;
    private static int totalQuarantined = 0;
    private static boolean useCache = true;

    private static boolean isSystemPath(String path) {
        if (path == null) return false;
        if (PROTECTED_PREFIXES == null) {
            PROTECTED_PREFIXES = new String[]{
                System.getProperty("user.home") + "/antivirus",
                "/home/felipe/antivirus",
                "/home/felipe/antivirus/src",
                "/home/felipe/antivirus/out"
            };
        }
        path = path.replace("\\", "/");
        for (String prefix : PROTECTED_PREFIXES) {
            if (path.startsWith(prefix.replace("\\", "/"))) return true;
        }
        return false;
    }

    public AntivirusScanner() {
        this(true);
    }

    public AntivirusScanner(boolean autoDelete) {
        this.autoDelete = autoDelete;
        this.entropyAnalyzer = new EntropyAnalyzer();
        this.peAnalyzer = new PEAnalyzer();
        this.extensionChecker = new ExtensionChecker();
        this.quarantineManager = new QuarantineManager();
        this.processKiller = new ProcessKiller();
        this.logger = AntivirusLogger.getInstance();
        this.sandboxExecutor = new SandboxExecutor();
        this.yaraScanner = new YaraScanner();
        this.sandboxAvailable = sandboxExecutor.getSandboxType() != SandboxExecutor.SandboxType.NATIVE;
        HashCache.init();
        DirectoryCache.init();
        this.logger.info(AntivirusLogger.Category.SYSTEM, "Cache carregado: " + HashCache.size() + " entradas");
        this.logger.info(AntivirusLogger.Category.SYSTEM, "Dir cache: " + DirectoryCache.size() + " diretorios");

        this.logger.info(AntivirusLogger.Category.SYSTEM, "Antivirus iniciado (auto-delete: " + autoDelete + ")");
        this.logger.info(AntivirusLogger.Category.SYSTEM, "YARA carregado: " + yaraScanner.getRuleCount() + " regras");
        if (sandboxAvailable) {
            this.logger.info(AntivirusLogger.Category.SYSTEM,
                "Sandbox disponivel: " + sandboxExecutor.getSandboxType());
        } else {
            this.logger.warn(AntivirusLogger.Category.SYSTEM,
                "Sandbox NAO disponivel - execucao sera feita sem isolamento");
        }
    }

    public void setAutoDelete(boolean autoDelete) {
        this.autoDelete = autoDelete;
    }

    public static int[] getStats() {
        return new int[]{totalScanned, totalDeleted, totalQuarantined};
    }

    public static void printStats() {
        System.out.println("Estatisticas: " + totalScanned + " escaneados, " + totalDeleted + " deletados, " + totalQuarantined + " quarentena");
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
        Path path = Path.of(filePath).toAbsolutePath().normalize();

        PathValidator.ValidationResult validation = PathValidator.validateFileOperation(path, PathValidator.Operation.READ);
        if (!validation.valid) {
            return new ScanResult(
                Path.of(filePath).getFileName().toString(),
                0,
                0,
                List.of(),
                false,
                false,
                "SEGURO",
                List.of("Arquivo invalido: " + validation.error),
                false,
                false
            );
        }

        if (useCache && HashCache.isCached(path)) {
            String cachedResult = HashCache.getCachedResult(path);
            if (cachedResult != null) {
                return new ScanResult(
                    path.getFileName().toString(),
                    0,
                    0,
                    List.of(),
                    false,
                    false,
                    cachedResult,
                    List.of("Cache"),
                    false,
                    false
                );
            }
        }

        long fileSize;
        try {
            if (Files.isDirectory(path)) {
                if (PathValidator.isSymlink(path)) {
                    return new ScanResult(
                        path.getFileName().toString(),
                        0,
                        0,
                        List.of(),
                        false,
                        false,
                        "SEGURO",
                        List.of("Diretorio symlink ignorado"),
                        false,
                        false
                    );
                }
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

        List<String> suspiciousStrings = Collections.emptyList();
        List<String> passwordStealerPatterns = Collections.emptyList();
        BoyerMooreStringDetector.MalwareCategory category = BoyerMooreStringDetector.MalwareCategory.UNKNOWN;
        int categoryScore = 0;

        if (entropy > 6.5) {
            suspiciousStrings = BoyerMooreStringDetector.detectSuspicious(fileData);
            passwordStealerPatterns = BoyerMooreStringDetector.detectPasswordStealer(fileData);
            category = BoyerMooreStringDetector.detectCategory(fileData);
            categoryScore = BoyerMooreStringDetector.getCategoryScore(fileData);
        }

        boolean doubleExtension = extensionChecker.check(fileName);
        boolean fakeFilename = checkFakeFilename(fileName);
        PEAnalysis peAnalysis = peAnalyzer.analyze(fileData);

        int score = calculateThreatScore(entropy, suspiciousStrings.size(), doubleExtension, peAnalysis, passwordStealerPatterns.size());
        
        if (fakeFilename) {
            score += 60;
            threats.add("Nome falso detectado!");
        }
        
        if (categoryScore > 0) {
            score += categoryScore;
        }

        List<String> yaraMatches = yaraScanner.scan(fileData);
        int yaraScore = 0;
        if (entropy > 6.5) {
            yaraScore = yaraScanner.getTotalScore(fileData, 40);
        }
        if (yaraScore > 0) {
            score += yaraScore;
            threats.add("YARA: " + yaraMatches);
        }
        
        String threatLevel = getThreatLevel(score);
        threats.addAll(buildThreats(entropy, suspiciousStrings, doubleExtension, peAnalysis, passwordStealerPatterns, category));

        boolean quarantined = false;
        boolean processKilled = false;
        boolean sandboxExecuted = false;

        if (runSandbox && sandboxAvailable && score >= 20 && peAnalysis.isValidPE()) {
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

        if (autoAction && score >= 20) {
            if (!isSystemPath(filePath) && autoDelete) {
                quarantined = quarantineManager.delete(filePath);
                if (quarantined) {
                    totalDeleted++;
                    threats.add("Arquivo DELETADO");
                    logger.logQuarantine(filePath, "DELETADO - Score: " + score);
                }
            } else {
                quarantined = quarantineManager.quarantine(filePath);
                if (quarantined) {
                    totalQuarantined++;
                    threats.add("Arquivo movido para quarentena");
                    logger.logQuarantine(filePath, "Score: " + score);
                }
            }
            
            if (score >= 80 && !isSystemPath(filePath)) {
                processKilled = processKiller.killByPath(filePath);
                if (processKilled) {
                    threats.add("Processo encerrado");
                    logger.logProcessKilled(-1, "Score CRITICO: " + score);
                }
            }
        }
        totalScanned++;

        logger.logScan(filePath, threatLevel, threats);
        if (useCache) {
            HashCache.put(path, threatLevel);
            HashCache.save();
        }

        return new ScanResult(
            fileName,
            fileData.length,
            entropy,
            suspiciousStrings,
            doubleExtension,
            peAnalysis.isValidPE(),
            threatLevel,
            score,
            threats,
            quarantined,
            processKilled,
            score >= 120
        );
    }

    private int calculateThreatScore(double entropy, int suspiciousCount, boolean doubleExt, PEAnalysis peAnalysis, int passwordStealerCount) {
        int score = 0;
        if (entropy > 8.2) score += 40;
        else if (entropy > 7.9) score += 15;
        if (suspiciousCount >= 4) score += 30;
        else if (suspiciousCount >= 6) score += 10;
        if (doubleExt) score += 50;
        if (peAnalysis.hasPackerSections()) score += 30;
        if (peAnalysis.hasWriteAndExecute()) score += 35;

        if (passwordStealerCount >= 6) score += 40;
        else if (passwordStealerCount >= 4) score += 20;

        return score;
    }

    private boolean checkFakeFilename(String fileName) {
        String lower = fileName.toLowerCase();
        if (lower.contains(".exe") && !lower.endsWith(".exe")) return true;
        if (lower.contains(".pdf") && lower.contains(".exe")) return true;
        if (lower.contains(".doc") && lower.contains(".exe")) return true;
        if (lower.contains(".jpg") && lower.contains(".exe")) return true;
        if (lower.contains(".mp3") && lower.contains(".exe")) return true;
        if (lower.contains(".mp4") && lower.contains(".exe")) return true;
        if (lower.contains(".zip") && lower.contains(".exe")) return true;
        
        String[] fakeNames = {"update", "patch", "crack", "keygen", "license", "activator", "free", "gift", "generator"};
        for (String fake : fakeNames) {
            if (lower.contains(fake + ".exe")) return true;
        }
        return false;
    }

    private String getThreatLevel(int score) {
        if (score >= 120) return "CRITICO";
        if (score >= 85) return "ALTO";
        if (score >= 55) return "MEDIO";
        if (score >= 20) return "BAIXO";
        return "SEGURO";
    }

    private boolean tryScanZipFile(String filePath) {
        try {
            Path path = Path.of(filePath);
            if (!path.toFile().isFile()) return false;

            byte[] data = Files.readAllBytes(path);
            double entropy = entropyAnalyzer.calculateEntropy(data);
            List<String> strings = BoyerMooreStringDetector.detectSuspicious(data);
            boolean doubleExt = extensionChecker.check(path.getFileName().toString());

            int score = 0;
            if (entropy > 8.2) score += 40;
            if (strings.size() >= 4) score += 20;
            if (doubleExt) score += 50;

            return score >= 35;
        } catch (Exception e) {
            return false;
        }
    }

    private List<String> buildThreats(double entropy, List<String> suspicious, boolean doubleExt, PEAnalysis pe, List<String> passwordStealer, BoyerMooreStringDetector.MalwareCategory category) {
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
        if (category != BoyerMooreStringDetector.MalwareCategory.UNKNOWN && category != BoyerMooreStringDetector.MalwareCategory.SUSPICIOUS) {
            threats.add("Categoria: " + category);
        }
        return threats;
    }

    public List<ScanResult> scanDirectory(String dirPath, boolean autoAction) throws IOException {
        return scanDirectory(dirPath, autoAction, false);
    }

    private static final String[] SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/tmp", "/usr/lib", "/usr/share", "/lib", "/share", "/snap", "/var/cache"};
    private static final String[] SKIP_EXT = {".pak", ".map", ".bin", ".elf", ".so", ".a", ".o", ".dll", ".sys", ".dylib", ".deb", ".rpm", ".appimage"};
    private static final String[] KNOWN_SAFE_NAMES = {"libc", "kernel", "system", "boot", "init", "udev", "dbus", "glibc", "gcc", "clang", "llvm", "arduino", "esp-idf", "platformio"};
    private static final String[] SKIP_PATH_CONTAINS = {".gradle", "node_modules", "vendor/bundle", "target/debug", "target/release", ".cargo/registry", ".rustup"};

    private static final int BATCH_SIZE = 100;
    private static final long MIN_SIZE_FOR_PARALLEL = 50 * 1024;
    private static final int PARALLEL_THRESHOLD = 5;

    public List<ScanResult> scanDirectory(String dirPath, boolean autoAction, boolean runSandbox, boolean useCache) throws IOException {
        List<ScanResult> results = new ArrayList<>();
        Path basePath = Path.of(dirPath).toAbsolutePath().normalize();
        long startTime = System.currentTimeMillis();

        if (!Files.exists(basePath)) {
            System.out.println("Diretorio nao existe: " + dirPath);
            return results;
        }

        if (PathValidator.isSymlink(basePath)) {
            System.out.println("Diretorio e symlink - ignorado por seguranca: " + dirPath);
            return results;
        }

        if (!Files.isDirectory(basePath)) {
            System.out.println("Nao e um diretorio: " + dirPath);
            return results;
        }

        System.out.println("Escaneando: " + dirPath);
        long totalFiles = 0;
        
        int processed = 0;
        int batchNum = 0;
        int countSeg = 0, countBaixo = 0, countMedio = 0, countAlto = 0, countCrit = 0;
        long batchStartTime = startTime;
        long batchStartRam = 0;

        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", 
                    "find '" + dirPath + "' -type f 2>/dev/null");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
            List<Path> batch = new ArrayList<>(BATCH_SIZE);
            String line;
            
            while ((line = br.readLine()) != null) {
                Path file = Path.of(line);
                if (shouldSkip(file)) continue;

                batch.add(file);
                totalFiles++;
                processed++;

                if (batch.size() >= BATCH_SIZE) {
                    long batchStartMs = System.currentTimeMillis();
                    List<ScanResult> batchResults = scanBatch(batch, autoAction, runSandbox, useCache);
                    results.addAll(batchResults);

                    for (ScanResult r : batchResults) {
                        String s = r.getScore();
                        if (s != null) {
                            switch (s) {
                                case "SEGURO" -> countSeg++;
                                case "BAIXO" -> countBaixo++;
                                case "MEDIO" -> countMedio++;
                                case "ALTO" -> countAlto++;
                                case "CRITICO" -> countCrit++;
                            }
                        }
                    }
                    batchNum++;

                    Runtime rt = Runtime.getRuntime();
                    long ramMB = (rt.totalMemory() - rt.freeMemory()) / (1024*1024);
                    long totalElapsed = (System.currentTimeMillis() - startTime) / 1000;
                    int totalThreats = countBaixo + countMedio + countAlto + countCrit;
                    System.out.printf("Lote: %02d | Arquivos: %d | Ram: %dMB | Ameacas: %d | Tempo: %ds%n",
                        batchNum, processed, ramMB, totalThreats, totalElapsed);

                    batch.clear();
                }
            }

             if (!batch.isEmpty()) {
                 List<ScanResult> batchResults = scanBatch(batch, autoAction, runSandbox, useCache);
                 results.addAll(batchResults);

                 for (ScanResult r : batchResults) {
                     String s = r.getScore();
                     if (s != null) {
                         switch (s) {
                             case "SEGURO" -> countSeg++;
                             case "BAIXO" -> countBaixo++;
                             case "MEDIO" -> countMedio++;
                             case "ALTO" -> countAlto++;
                             case "CRITICO" -> countCrit++;
                         }
                     }
                 }
             }

            System.out.println();

            p.waitFor();
            
        } catch (Exception e) {
            System.err.println("Erro: " + e.getMessage());
        }

        long elapsedMs = System.currentTimeMillis() - startTime;
        double seconds = elapsedMs / 1000.0;
        double filesPerSec = totalFiles > 0 && seconds > 0 ? totalFiles / seconds : 0;

        System.out.println();
        System.out.println("TEMPO TOTAL: " + String.format("%.1f", seconds) + "s | " + String.format("%.0f", filesPerSec) + " arquivos/s");
        System.out.println("SEGURO: " + countSeg + " | BAIXO: " + countBaixo + " | MEDIO: " + countMedio + " | ALTO: " + countAlto + " | CRITICO: " + countCrit);

        if (totalFiles > 0) {
            int threats = countBaixo + countMedio + countAlto + countCrit;
            String status = threats > 0 ? "AMEACA" : "SEGURO";
            DirectoryCache.markDirectory(dirPath, status);
        }

        return results;
    }

    private static void printProgress(int processed, int threats) {
        System.out.println("[PROGRESSO] Arquivos: " + processed + " | Ameacas: " + threats);
    }

    private List<ScanResult> scanBatch(List<Path> files, boolean autoAction, boolean runSandbox) {
        if (files.size() < PARALLEL_THRESHOLD) {
            return scanBatchSequential(files, autoAction, runSandbox);
        }

        List<ScanResult> batchResults = Collections.synchronizedList(new ArrayList<>());
        int threads = Math.max(4, Math.min(Runtime.getRuntime().availableProcessors(), 16));
        ForkJoinPool pool = new ForkJoinPool(threads);
        try {
            pool.submit(() -> files.parallelStream().forEach(p -> {
                try {
                    ScanResult r = scanFile(p.toString(), autoAction, runSandbox);
                    String score = r.getScore();
                    if (score != null && !score.equals("SEGURO")) {
                        batchResults.add(r);
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
        return new ArrayList<>(batchResults);
    }

    private List<ScanResult> scanBatchSequential(List<Path> files, boolean autoAction, boolean runSandbox) {
        List<ScanResult> batchResults = new ArrayList<>();
        for (Path p : files) {
            try {
                ScanResult r = scanFile(p.toString(), autoAction, runSandbox);
                String score = r.getScore();
                if (score != null && !score.equals("SEGURO")) {
                    batchResults.add(r);
                }
            } catch (Exception e) {
                // silent
            }
        }
        return batchResults;
    }

    private boolean shouldSkip(Path path) {
        try {
            if (PathValidator.isSymlink(path)) return true;
        } catch (Exception e) {
            return true;
        }

        String pathStr = path.toString();
        String lower = pathStr.toLowerCase();
        for (String skip : SKIP_DIRS) {
            if (lower.contains(skip.toLowerCase())) {
                return true;
            }
        }
        for (String skip : SKIP_PATH_CONTAINS) {
            if (lower.contains(skip)) {
                return true;
            }
        }
        String fileName = path.getFileName().toString().toLowerCase();
        for (String ext : SKIP_EXT) {
            if (fileName.endsWith(ext)) {
                return true;
            }
        }
        for (String safe : KNOWN_SAFE_NAMES) {
            if (fileName.contains(safe)) {
                try {
                    long size = Files.size(path);
                    if (size > 1024 * 1024) return true;
                } catch (Exception e) {}
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

        if (args[0].equals("-h") || args[0].equals("--help")) {
            System.out.println("""
                HeapSec Antivirus - Ajuda
                ========================

                USO:
                    ./heapsec [opcoes] <arquivo ou diretorio>

                OPCOES:
                    -h, --help           Esta ajuda
                    -l, --logs           Ver logs
                    -w, --watch          Watch logs em tempo real
                    --daemon <path>      Modo daemon (monitoramento)
                    --no-action          Desativar auto-delete
                    --no-cache           Nao usar cache
                    --sandbox            Executar em sandbox
                    -d, --decompress      Varredura pesada (ZIP/JAR)

                EXEMPLOS:
                    ./heapsec arquivo.exe
                    ./heapsec /home/felipe/Downloads
                    ./heapsec arquivo.exe --action
                    ./heapsec --no-cache /home/felipe/Downloads
                """);
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
            boolean autoQuar = true;
            for (int i = 2; i < args.length; i++) {
                if (args[i].equals("--no-action")) autoQuar = false;
            }
            System.out.println("Daemon mode: " + watchPath + " | Auto-quarentena: " + autoQuar);
            AntivirusScanner sc = new AntivirusScanner();
            startDaemon(sc, watchPath, autoQuar);
            return;
        }

        boolean autoAction = true;
        boolean runSandbox = false;
        boolean decompress = false;
        useCache = true;

        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--no-action")) autoAction = false;
            else if (args[i].equals("--sandbox")) runSandbox = true;
            else if (args[i].equals("-d") || args[i].equals("--decompress")) decompress = true;
            else if (args[i].equals("--no-cache")) useCache = false;
        }

        Path path = Path.of(args[0]);

        if (Files.isDirectory(path)) {
            List<ScanResult> results = scanner.scanDirectory(args[0], autoAction, runSandbox);
        } else {
            ScanResult result = scanner.scanFile(args[0], autoAction, runSandbox, decompress);
            if (!result.getScore().equals("SEGURO")) {
                System.out.println(result.getFileName() + " -> " + result.getScore());
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
                        System.out.println(logs.get(System.out.println(logs.get(i));
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

private static void loadBannerFromHome() {
        try {
            String homeBanner = System.getProperty("user.home") + "/.antivirus/banner.txt";
            String banner = Files.readString(Path.of(homeBanner));
            System.out.println(banner);
        } catch (Exception e) {
            System.out.println("HEAPSEC");
        }
    }

    private static void printBanner() {
        loadBannerFromHome();
    }

    private static void printMenu() {
        printBanner();
        System.out.println("""
                [1] arquivo     - escanear arquivo
                [2] diretorio   - escanear diretorio
                [3] quarantine  - listar quarentena
                [4] logs        - ver logs
                [5] watch       -monitorar tempo real
                [6] cache       - limpar cache
                [7] help       - ajuda
                [0] quit       - sair
                """);
    }

    private static void runInteractiveMenu(AntivirusScanner scanner, Scanner input) {
        while (true) {
            printMenu();
            System.out.print("> ");
            
            String choice;
            try {
                if (!input.hasNextLine()) break;
                choice = input.nextLine().trim();
            } catch (Exception e) {
                break;
            }

            if (choice.isEmpty()) continue;

            switch (choice) {
                 case "1", "file" -> {
                     System.out.print("Arquivo: ");
                     String f = input.nextLine().trim();
                     if (!f.isEmpty()) {
                         System.out.print("Acao (D)eletar/(Q)uarentenar/(N)ada? (D): ");
                         String aq = input.nextLine().trim().toLowerCase();
                         boolean autoAction = !aq.equals("n");
                         if (aq.equals("q")) scanner.setAutoDelete(false);
                         else scanner.setAutoDelete(true);
                         
                         System.out.print("Usar cache? (S/n): ");
                         String useCacheInput = input.nextLine().trim().toLowerCase();
                         boolean useCache = !useCacheInput.equals("n");
                         
                         try { 
                             System.out.println(scanner.scanFile(f, autoAction, false, useCache)); 
                         } 
                         catch (Exception e) { System.out.println("Erro: " + e.getMessage()); }
                     }
                 }
                 case "2", "dir" -> {
                     System.out.print("Diretorio [/home/felipe]: ");
                     String d = input.nextLine().trim();
                     if (d.isEmpty()) d = System.getenv("HOME");
                     else if (!d.startsWith("/")) d = System.getenv("HOME") + "/" + d;
                     System.out.print("Acao (D)eletar/(Q)uarentenar/(N)ada? (D): ");
                     String aq = input.nextLine().trim().toLowerCase();
                     boolean autoAction = !aq.equals("n");
                     if (aq.equals("q")) scanner.setAutoDelete(false);
                     else scanner.setAutoDelete(true);
                     
                     System.out.print("Usar cache? (S/n): ");
                     String useCacheInput = input.nextLine().trim().toLowerCase();
                     boolean useCache = !useCacheInput.equals("n");
                     
                     System.out.println("Escaneando: " + d);
                     try { 
                         var r = scanner.scanDirectory(d, autoAction, false, useCache);
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
                case "3", "quarantine" -> scanner.getQuarantineManager().listQuarantined();
                case "4", "logs" -> AntivirusLogger.getInstance().getLogs().forEach(System.out::println);
                case "5", "watch" -> watchLogs();
                case "6", "cache" -> {
                    System.out.print("Limpar cache? (S/n): ");
                    if (input.nextLine().trim().equalsIgnoreCase("s")) {
                        HashCache.clear();
                        System.out.println("Cache limpo");
                    }
                }
                case "7", "help" -> printMenu();
                case "0", "quit" -> { return; }
                default -> {
                    // Try to scan as path
                    Path p = Path.of(choice);
                    if (Files.exists(p)) {
                        try { System.out.println(scanner.scanFile(choice, false, false, false)); } 
                        catch (Exception e) { System.out.println("Erro: " + e.getMessage()); }
                    } else {
                        System.out.println("Comando invalido");
                    }
                }
            }
        }
    }
}

