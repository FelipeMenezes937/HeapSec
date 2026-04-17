# InfoVirus Antivirus

Scanner antivírus heurístico 100% local em Java 21.

## arquitetura

```
┌─────────────────────────────────────────┐
│  CAMADA 1: HEURÍSTICA RÁPIDA            │
│  - Entropy, magic headers, extensions    │
│  - ~95% arquivos passam aqui           │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│  CAMADA 2: ANÁLISE PROFUNDA             │
│  - Strings, PE analysis               │
│  - Batch processing paralelo         │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│  CAMADA 3: SANDBOX (sob demanda)       │
│  - Execução isolada                    │
│  - Análise comportamental             │
└─────────────────────────────────────────┘
```

## Uso

```bash
./antivirus                  # Menu interativo
./antivirus arquivo.exe     # Escanear arquivo
./antivirus /pasta         # Escanear diretório
./antivirus arquivo.exe --action  # Escanear + quarentena
./antivirus -l             # Ver logs
./antivirus -w            # Watch logs em tempo real
./antivirus -d            # Modo daemon (background)
./antivirus -h            # Ajuda
```

## Detecção

| Sinal | Condição | Score |
|-------|----------|-------|
| Magic unknown + alta entropia | - | +40 |
| Extensão dupla | .pdf.exe | +50 |
| Strings suspeitas | 2+ padrões | +20 |
| Packer sections | UPX, Themida | +30 |
| Write+Execute | Seção PE | +35 |
| Password patterns | 2+ | +40 |

## Score de Ameaça

| Score | Classificação | Confidence |
|-------|--------------|------------|
| 0-24 | SEGURO | 95% |
| 25-44 | BAIXO | 70% |
| 45-69 | MEDIA | 75% |
| 70-99 | ALTO | 85% |
| 100+ | CRITICO | 90% |

## Redução de Falso Positivo

- Magic header validation (ZIP/JAR legítimos ignorados)
- Extensões ignoradas: .pak, .map, .bin, .elf
- Diretórios ignorados: node_modules, .cache, .gradle
- Categoria só com 4+ padrões (antes 3+)
- Arquivos > 50MB ignorados

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
│   └── MalwareDetector.java
└── action/
    └── QuarantineManager.java
```