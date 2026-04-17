# InfoVirus Antivirus Module - Análise Heurística Local

## Visão Geral

Módulo de análise antivírus que opera 100% localmente, sem necessidade de APIs externas, usando técnicas heurísticas para detectar arquivos suspeitos.

## Técnicas de Detecção

### 1. Entropia de Shannon

```javascript
function calculateEntropy(buffer) {
    const freq = new Array(256).fill(0);
    for (const byte of buffer) freq[byte]++;
    
    let entropy = 0;
    for (const f of freq) {
        if (f > 0) {
            const p = f / buffer.length;
            entropy -= p * Math.log2(p);
        }
    }
    return entropy;
}
```

| Entropia | Interpretação |
|---------|-------------|
| 0-4.0 | Arquivo normal/texto |
| 4.0-6.0 | Possível packing leve |
| 6.0-7.5 | Alta probabilidade de packer/criptografia |
| 7.5-8.0 | Quase certeza de código ofuscado ou packer |

### 2. Deteção de Strings Suspeitas

```javascript
const SUSPICIOUS_PATTERNS = [
    /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,  // IP externo
    /cmd\.exe/i,
    /powershell/i,
    /wscript/i,
    /cscript/i,
    /certutil/i,
    /bitsadmin/i,
    /whoami/i,
    /net\s+user/i,
    /reg\s+add/i,
    /vssadmin/i,
    /mimikatz/i,
    /Base64/i,
    /frombase64string/i,
    /encodedcommand/i,
    /downloadstring/i,
    /invoke-webrequest/i,
    /new-object\s+net\.webclient/i,
    /IEX\s+new-object/i,
    /<script[^>]*>/i,
    /eval\s*\(/i,
    /exec\s*\(/i,
    /system\s*\(/i,
    /passthru/i
];
```

### 3. Extensões Gêmeas

```javascript
const DOUBLE_EXTENSIONS = [
    '.pdf.exe', '.doc.exe', '.xls.exe', '.ppt.exe',
    '.jpg.exe', '.png.exe', '.gif.exe',
    '.html.exe', '.zip.exe', '.rar.exe',
    '.js.exe', '.vbs.exe', '.bat.exe'
];
```

### 4. Headers PE (Portable Executable)

```javascript
function detectPeHeader(buffer) {
    const mz = buffer.slice(0, 2).toString();
    if (mz !== 'MZ') return false;
    
    const peOffset = buffer.readUInt32LE(60);
    const pe = buffer.slice(peOffset, peOffset + 2).toString();
    return pe === 'PE';
}
```

### 5. Análise de Seção PE

Verificar seções suspeitas em executáveis:
- `.upx`, `.aspack`, `.petite` = packer instalado
- `Write` + `Execute` + Resource = potencialmente malicioso

## Arquitetura

```
antivirus/
├── index.js              # Entry point
├── heuristics/
│   ├── entropy.js       # Cálculo de entropia
│   ├── strings.js       # Detecção de strings
│   ├── pe.js           # Análise PE
│   └── extension.js     # Extensões suspeitas
├── scanner.js           # Scanner principal
└── rules.js            # Regras de detecção
```

## Score de Ameaça

```javascript
function calculateThreatScore(results) {
    let score = 0;
    
    if (results.entropy > 7.5) score += 40;
    if (results.entropy > 6.0) score += 20;
    if (results.suspiciousStrings > 3) score += 30;
    if (results.suspiciousStrings > 0) score += 10;
    if (results.doubleExtension) score += 50;
    if (results.hasPackerSections) score += 30;
    if (results.writeAndExecute) score += 40;
    
    // Classificação
    if (score >= 80) return 'CRITICO';
    if (score >= 50) return 'ALTO';
    if (score >= 30) return 'MEDIO';
    if (score >= 10) return 'BAIXO';
    return 'SEGURO';
}
```

## Exemplo de Uso

```javascript
const scanner = require('./scanner');

const results = await scanner.scanFile('/caminho/arquivo.exe');

console.log(results);
// {
//   file: 'arquivo.exe',
//   size: 45056,
//   entropy: 7.82,
//   suspiciousStrings: ['powershell', 'Base64'],
//   doubleExtension: false,
//   isPe: true,
//   score: 'ALTO',
//   threats: ['Alta entropia (7.82)', 'Strings suspeitas']
// }
```

## Escaneamento Recursivo de Pasta

```javascript
const fs = require('fs');
const path = require('path');

async function scanDirectory(dirPath, options = {}) {
    const results = [];
    const maxDepth = options.maxDepth || 3;
    
    async function walk(dir, depth = 0) {
        if (depth > maxDepth) return;
        
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            
            if (entry.isDirectory()) {
                await walk(fullPath, depth + 1);
            } else if (entry.isFile()) {
                const result = await scanner.scanFile(fullPath);
                if (result.score !== 'SEGURO') {
                    results.push(result);
                }
            }
        }
    }
    
    await walk(dirPath);
    return results;
}
```

## Integração com InfoVirus

O módulo pode ser adicionado como nova ferramenta "Antivírus" no frontend:

```javascript
// Novo endpoint
app.post('/api/antivirus', antivirusController.scanFile);
app.post('/api/antivirus/dir', antivirusController.scanDirectory);
```

## Limitações Conhecidas

- Não detecta malware polimórfico avançado
- Falsos positivos em arquivos legítimos compressionados
- Não substitui antivírus tradicional
- Útil como camada adicional de detecção

## TO-DO

- [ ] Implementar módulos individuais
- [ ] Adicionar regras YARA (opcional)
- [ ] Criar interface no frontend
- [ ] Adicionarendpoint na API
- [ ] Testar com amostras de teste (GitHub: eicar-com/eicar)

## Referências

- Shannon Entropy: https://en.wikipedia.org/wiki/Entropy_(information_theory)
- PE Format: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- UPX Packer: https://upx.github.io/
