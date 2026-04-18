# HeapSec Antivirus

Scanner antivírus heurístico 100% local em Java 21.
> Forja de bytes - análise profunda e eficiente

## Instalação

O binaryempacotado está disponível em `out/aot/heapsec_1.1.0_amd64.deb`

Para instalar:
```bash
sudo dpkg -i out/aot/heapsec_1.1.0_amd64.deb
heapsec
```

## Uso

### CLI (Linha de Comando)

```bash
heapsec                          # Menu interativo
heapsec arquivo.exe              # Escanear arquivo
heapsec /home/downloads           # Escaneia diretório
heapsec /path --no-action         # Sem auto-delete
heapsec -h                        # Ajuda
heapsec -l                        # Ver logs
heapsec -w                        # Watch logs em tempo real
```

### Menu Interativo

```
> 2
Diretorio [/home/felipe]: /home/felipe/Downloads
Acao (D)eletar/(Q)uarentenar/(N)ada? (D): n
Escaneando: /home/felipe/Downloads
[PROGRESSO] Arquivos: 1000 | Ameacas: 5
[PROGRESSO] Arquivos: 2000 | Ameacas: 12

╔══════════════════════════════════════════════════════╗
║           RESULTADO DO ESCANEAMENTO                 ║
╠══════════════════════════════════════════════════════╣
║  5000 arquivos escaneados em 2,8s (1785 arquivos/s)   ║
╠══════════════════════════════════════════════════════╣
║  SEGURO:     4890 (97,8%)                             ║
║  BAIXO:        72 (1,4%)                              ║
║  MEDIO:         8 (0,2%)                               ║
║  ALTO:          5 (0,1%)                               ║
║  CRITICO:       2 (0,0%)                              ║
╚══════════════════════════════════════════════════════╝
```

## Detecção

### Técnicas
- **Entropia de Shannon**: Detecta empacotamento (>7.8)
- **YARA patterns**: 60+ regras para malware e ferramentas de hacking
- **Aho-Corasick**: Busca multi-padrão O(n)
- **Extensão dupla**: .pdf.exe, .doc.exe, etc
- **Análise PE**: Seções de packer, write+execute

### Categorias Detectadas
- Password Stealers
- RATs (Remote Access Trojans)
- Keyloggers
- Bankers
- Cryptominers
- Droppers
- Spyware
- Botnets
- Ransomware

### Score de Ameaça

| Score | Classificação |
|-------|----------------|
| 0-19 | SEGURO |
| 20-54 | BAIXO |
| 55-84 | MÉDIO |
| 85-119 | ALTO |
| 120+ | CRÍTICO |

## Features

- **Progresso em Tempo Real**: Atualiza a cada batch (1000 arquivos)
- **Hash Cache**: Arquivos já escaneados são cacheados
- **Aho-Corasick**: Busca multi-padrão otimizada
- **Path Validation**: Segurança contra path traversal e symlinks
- **Skips Inteligentes**: node_modules, .gradle, binaries grandes
- **Menu Interativo Completo**: Scan, quarantine, logs, watch

## Performance

- **Velocidade**: ~1.800 arquivos/segundo
- **Memória**: ~400MB (parallel ForkJoinPool)
- **Batch**: 1000 arquivos por lote
- **Parallel**: 10+ arquivos → ForkJoinPool

## Estrutura

```
src/main/java/antivirus/
├── AntivirusScanner.java      # Main + CLI + menu
├── scanner/
│   ├── EntropyAnalyzer.java   # Entropia de Shannon
│   ├── BoyerMooreStringDetector.java  # Aho-Corasick
│   ├── YaraScanner.java       # Regras YARA
│   ├── PEAnalyzer.java        # Análise PE
│   ├── ExtensionChecker.java  # Extensões duplas
│   ├── HashCache.java         # Cache de resultados
│   └── ZipExtractor.java      # Extrai ZIP/JAR
├── action/
│   └── QuarantineManager.java # Quarentena
└── security/
    └── PathValidator.java    # Validação de paths
```

## Segurança

- Validação de symlinks (evita symlink attack)
- Canonical path resolve (evita path traversal)
- Limite de ratio em extração ZIP (evita zip bombs)
- Cache com validação de tamanho/integidade
- Sanitização de paths em logs