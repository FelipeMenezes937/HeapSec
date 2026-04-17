# InfoVirus Antivirus

Scanner antivírus heurístico 100% local em Java 21.

## Funcionalidades

- **Análise de Entropia** - Detecta arquivos empacotados/criptografados (Shannon entropy)
- **Detecção de Strings** - Padrões suspeitos (powershell, mimikatz, cmd.exe, etc)
- **Verificação de Extensão Dupla** - Arquivos disfarçados (.pdf.exe, .doc.exe)
- **Análise de Headers PE** - Seções perigosas (Write+Execute), packers (.upx, .aspack)
- **Quarentena** - Move arquivos suspeitos para ~/.antivirus/quarantine
- **Execução em Sandbox** - Executa arquivos em ambiente isolado (firejail/gvisor/docker)
- **Logging Centralizado** - Logs de todas as operações em ~/.antivirus/logs
- **Categorização de Malware** - Detecta tipos (password stealer, ransomware, rat, etc)
- **Watch Mode** - Logs em tempo real (como htop)

## Técnicas de Detecção

| Técnica | Condição | Pontuação |
|---------|----------|----------|
| Entropia alta | > 7.5 | +40 |
| Entropia média | > 6.0 | +20 |
| Strings suspeitas | > 3 encontrados | +30 |
| Extensão dupla | .pdf.exe etc | +50 |
| Seções de packer | .upx, .aspack | +30 |
| Write + Execute | Seção PE perigosa | +40 |

### Categorias de Malware

| Categoria | Padrões | Score Extra |
|-----------|--------|-----------|
| RANSOMWARE | encrypt, bitcoin, locked files | +80 |
| RAT | backdoor, remote admin, njrat | +70 |
| PASSWORD_STEALER | password, logins, firefox | +60 |
| BANKER | bank, transfer, creditcard | +60 |
| CRYPTOMINER | miner, hash, pool | +50 |
| KEYLOGGER | keylog, hook, keystroke | +50 |
| BOTNET | botnet, ddos, zombie | +50 |
| SPYWARE | screenshot, webcam, monitor | +45 |
| DROPPER | download, payload, mshta | +40 |

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
├── sandbox/
│   └── SandboxExecutor.java # Execução em sandbox
├── logging/
│   └── AntivirusLogger.java # Logging centralizado
└── scanner/
    ├── EntropyAnalyzer.java  # Entropia de Shannon
    ├── ExtensionChecker.java # Extensões duplas
    ├── PEAnalyzer.java       # Headers PE
    ├── PEAnalysis.java       # Resultado de análise PE
    ├── ScanResult.java       # Modelo de resultado
    └── StringDetector.java   # Strings suspeitas + categorias
```

## Compilação

```bash
javac -d out/production/antivirus src/main/java/antivirus/**/*.java src/main/java/antivirus/*.java
```

## Uso

###CLI (wrapper)

```bash
./antivirus arquivo.exe                    # Escanear arquivo
./antivirus arquivo.exe --action          # Escanear + quarentena
./antivirus arquivo.exe --action --sandbox  # Escanear + quarentena + sandbox
./antivirus -l                         # Ver logs
./antivirus --logs                    # Ver logs
./antivirus -w                         # Watch logs tempo real (Ctrl+C)
./antivirus --watch                   # Watch logs tempo real
```

###Modo interativo

```bash
./antivirus
# Menu:
# 1. Escanear arquivo
# 2. Escanear diretorio
# 3. Ver quarentena
# 4. Ver logs
# 5. Sair
```

###Monitor de processos (contínuo)

```bash
java -cp out/production/antivirus antivirus.monitor.ProcessMonitor 10
```

Intervalo em segundos (padrão: 10).

## Sandbox

O antivirus detecta automaticamente o sandbox disponível:

| Prioridade | Sandbox | Restrições |
|------------|---------|------------|
| 1º | firejail | --private --private-tmp --net=none --caps.drop=all |
| 2º | gvisor (runsc) | --fs=readonly --net=none |
| 3º | docker | --network=none --read-only --cap-drop=ALL |
| 4º | unshare | --mount --pid --fork |
| 5º | native | nenhum isolamento |

## Logging

Logs保存在 `~/.antivirus/logs/`:

```bash
./antivirus -w  # Modo watch (tempo real)
./antivirus -l  # Ver todos os logs
```

## Testado com Malware Real

- **passwordfox.exe** - Detectado como PASSWORD_STEALER
- Score: 130 (CRITICO)
- Quarentena automática ativada

## Referências

- [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [UPX Packer](https://upx.github.io/)
- [firejail](https://firejail.rootkit.nl/)
- [gvisor](https://gvisor.dev/)