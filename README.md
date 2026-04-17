# InfoVirus Antivirus

Scanner antivírus heurístico 100% local em Java 21.

## Funcionalidades

- **Análise de Entropia** - Detecta arquivos empacotados/criptografados (Shannon entropy)
- **Detecção de Strings** - Padrões suspeitos (powershell, mimikatz, cmd.exe, etc)
- **Verificação de Extensão Dupla** - Arquivos disfarçados (.pdf.exe, .doc.exe)
- **Análise de Headers PE** - Seções perigosas (Write+Execute), packers (.upx, .aspack)
- **Quarentena** - Move arquivos suspeitos para ~/.antivirus/quarantine
- **Kill de Processos** - Encerra processos maliciosos automaticamente

## Técnicas de Detecção

| Técnica | Condição | Pontuação |
|---------|----------|----------|
| Entropia alta | > 7.5 | +40 |
| Entropia média | > 6.0 | +20 |
| Strings suspeitas | > 3 encontrados | +30 |
| Extensão dupla | .pdf.exe etc | +50 |
| Seções de packer | .upx, .aspack | +30 |
| Write + Execute | Seção PE perigosa | +40 |

## Score de Ameaça

| Score | Classificação |
|-------|----------------|
| 0-9 | SEGURO |
| 10-29 | BAIXO |
| 30-49 | MEDIO |
| 50-79 | ALTO |
| 80+ | CRITICO |

## Estrutura do Projeto

```
src/main/java/antivirus/
├── AntivirusScanner.java     # Main class (scanner)
├── action/
│   ├── ProcessKiller.java    # Encerra processos
│   └── QuarantineManager.java # Quarentena
├── monitor/
│   └── ProcessMonitor.java   # Monitor contínuo
└── scanner/
    ├── EntropyAnalyzer.java  # Entropia de Shannon
    ├── ExtensionChecker.java # Extensões duplas
    ├── PEAnalyzer.java       # Headers PE
    ├── ScanResult.java       # Modelo de resultado
    └── StringDetector.java   # Strings suspeitas
```

## Compilação

```bash
javac -d out/production/antivirus src/main/java/antivirus/**/*.java src/main/java/antivirus/*.java
```

## Usage

### Scanner de arquivo

```bash
java -cp out/production/antivirus antivirus.AntivirusScanner arquivo.exe
```

### Scanner com ação automática (quarentena + kill)

```bash
java -cp out/production/antivirus antivirus.AntivirusScanner arquivo.exe --action
```

### Escaneamento recursivo de diretório

```bash
java -cp out/production/antivirus antivirus.AntivirusScanner /caminho/pasta --recursive
```

### Monitor de processos (contínuo)

```bash
java -cp out/production/antivirus antivirus.monitor.ProcessMonitor 10
```

Intervalo em segundos (padrão: 10).

## Limitações

- Não detecta malware polimórfico avançado
- Falsos positivos em arquivos legítimos comprimidos
- Útil como camada adicional de detecção, não substitui antivírus tradicional

## Referências

- [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [UPX Packer](https://upx.github.io/)