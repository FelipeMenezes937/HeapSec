# HeapSec Antivirus

Scanner antivírus heurístico 100% local em Java 21.
> Forja de bytes - análise profunda e eficiente

## Uso

### CLI (Linha de Comando)

```bash
./heapsec                  # Menu interativo
./heapsec arquivo.exe     # Escanear arquivo
./heapsec /pasta         # Escaneia diretório automaticamente
./heapsec arquivo.exe --action  # Escanear + quarentena
./heapsec -l             # Ver logs
./heapsec -w            # Watch logs em tempo real
./heapsec -d            # Varredura pesada (ZIP/JAR)
./heapsec -D <path>    # Modo daemon (background)
./heapsec -h            # Ajuda
```

### Monitor de Processos

O monitor escanea processos em execução periodicamente:

```bash
java -cp target/classes antivirus.monitor.ProcessMonitor [intervalo_segundos]
```

Exemplo:
```bash
java -cp target/classes antivirus.monitor.ProcessMonitor 30
```

Opções do menu interativo (via CLI):
1. Escanear arquivo
2. Escanear diretório (lote)
3. Ver quarentena
4. Ver últimos logs
5. Watch logs em tempo real
6. Modo daemon (monitoramento de arquivos)
8. Sair

## Detecção

| Sinal | Condição | Score |
|-------|----------|-------|
| Magic unknown + alta entropia | > 7.8 | +40 |
| Extensão dupla | .pdf.exe | +50 |
| Strings suspeitas | 2+ padrões | +20 |
| Packer sections | UPX, Themida | +30 |
| Write+Execute | Seção PE | +35 |
| Password patterns | 2+ | +40 |

## Features

- **Barra de Progresso**: Visual em tempo real durante escaneamento (▓▓▓░░░)
- **Hash Cache**: Arquivos já escaneados são cacheados (evita re-escaneamento)
- **Varredura Pesada**: Flag `-d` prepara extração e análise de ZIPs/JARs
- **Modo Daemon**: Monitoramento em background com `-D`
- **Menu Interativo**: Interface com todas opções
- **Auto-detecção Diretório**: Passa diretório → escaneia automaticamente

## Score de Ameaça

| Score | Classificação | Confidence |
|-------|--------------|------------|
| 0-24 | SEGURO | 95% |
| 25-44 | BAIXO | 70% |
| 45-69 | MÉDIA | 75% |
| 70-99 | ALTO | 85% |
| 100+ | CRÍTICO | 90% |

## Redução de Falso Positivo

- Magic header validation (ZIP/JAR legítimos ignorados)
- Extensões ignoradas: .pak, .map, .bin, .elf
- Diretórios ignorados: node_modules, .cache, .gradle
- Categoria só com 4+ padrões
- Arquivos > 50MB ignorados
- Cache evita re-escaneamento

## Performance

- Memória: ~100MB (batch de 500 arquivos)
- Escaneamento: ~400 arquivos/segundo
- Batch processing com ForkJoinPool
- GC entre lotes

## Estrutura

```
src/main/java/antivirus/
├── AntivirusScanner.java     # Main
├── scanner/
│   ├── EntropyAnalyzer.java
│   ├── StringDetector.java
│   ├── HashCache.java
│   ├── ZipExtractor.java
│   └── MalwareDetector.java
└── action/
    └── QuarantineManager.java
```