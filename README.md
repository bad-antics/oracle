# 🔮 Oracle

**AI-Powered Predictive Vulnerability Discovery Engine**

[![Julia](https://img.shields.io/badge/Julia-1.10+-9558B2?logo=julia&logoColor=white)](https://julialang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Revolutionary-red.svg)]()

> Predict vulnerabilities before they're exploited. Oracle uses advanced machine learning to identify 0-day vulnerabilities through pattern analysis and anomaly detection.

## 🌟 Features

### 🧠 AI-Powered Analysis
- **Deep Code Embeddings** - Transform code into ML-ready vectors
- **Vulnerability Prediction** - Predict security issues with trained models
- **Anomaly Detection** - Identify unknown 0-day patterns using isolation forests
- **Pattern Classification** - Multi-class vulnerability classification

### 🔍 Comprehensive Analysis
- **Static Analysis** - AST-based pattern matching and dangerous function detection
- **Semantic Analysis** - Symbol tables, call graphs, and type inference
- **Data Flow Analysis** - Reaching definitions, live variables, def-use chains
- **Control Flow Analysis** - CFG construction, dominators, loop detection
- **Taint Tracking** - Full source-to-sink taint propagation

### 🛡️ Vulnerability Coverage
- SQL/Command Injection (CWE-89, CWE-78)
- Cross-Site Scripting (CWE-79)
- Buffer Overflow (CWE-120)
- Use After Free (CWE-416)
- Path Traversal (CWE-22)
- Insecure Deserialization (CWE-502)
- Authentication Bypass (CWE-287)
- Cryptographic Weaknesses (CWE-327)
- SSRF (CWE-918)
- And 6 more vulnerability classes...

### 📊 Risk Intelligence
- **CVSS Calculation** - Automatic severity scoring
- **Risk Prioritization** - Smart finding prioritization
- **CVE Correlation** - Link findings to known vulnerabilities
- **NVD Integration** - Real-time vulnerability database

### 📝 Reporting
- **HTML Reports** - Beautiful, interactive dashboards
- **SARIF Export** - CI/CD integration ready
- **JSON/Markdown** - Developer-friendly formats
- **Trend Analysis** - Track security posture over time

## 🚀 Quick Start

### Installation

```julia
using Pkg
Pkg.add(url="https://github.com/yourusername/oracle")
```

### Basic Usage

```julia
using Oracle

# Scan a single file
result = analyze("vulnerable.c")

# Scan entire codebase
result = scan_codebase("./src")

# Generate report
generate_report(result, format="html")
```

### Advanced Usage

```julia
using Oracle

# Configure scanner
config = ScanConfig(
    enable_ml=true,
    enable_anomaly=true,
    min_confidence=0.5,
    parallel=true
)

# Initialize scanner with custom config
scanner = Scanner(config=config)

# Scan with full analysis
result = scan(scanner, "./project")

# Prioritize findings
prioritizer = RiskPrioritizer()
prioritized = prioritize(prioritizer, result.findings)

# Correlate with CVEs
client = NVDClient(api_key=ENV["NVD_API_KEY"])
correlated = correlate_findings(client, result.findings)

# Generate comprehensive report
generator = ReportGenerator(output_dir="./reports")
generate_report(generator, result, format="html", target="MyProject")
```

## 🔬 How It Works

### Analysis Pipeline

```
│                        Oracle Pipeline                           │
│   │  Code   │───▶│  Tokenizer  │───▶│  AST Parser  │            │
│                        ▼                   ▼                   ▼ │
│              │    Static    │    │   Semantic   │    │   Data   ││
│              │   Analysis   │    │   Analysis   │    │   Flow   ││
│                                            ▼                     │
│                              │  Feature Vector  │                │
│                   ▼                  ▼                  ▼        │
│          │  Predictor   │   │  Classifier  │   │   Anomaly    │  │
│          │     (ML)     │   │  (Ensemble)  │   │  Detection   │  │
│                                      ▼                           │
│                           │    Findings      │                   │
│                           │  & Risk Scores   │                   │
│                                      ▼                           │
│                           │     Report       │                   │
│                           │   Generation     │                   │
```

### Machine Learning Components

1. **Code Embeddings** (`CodeEmbedder`)
   - Tokenizes code into semantic units
   - Generates 128-dimensional embeddings
   - Supports similarity search for pattern matching

2. **Vulnerability Predictor** (`VulnerabilityPredictor`)
   - Multi-label classification across 15 vulnerability types
   - Trained on historical vulnerability data
   - Heuristic initialization for zero-shot prediction

3. **Pattern Classifier** (`PatternClassifier`)
   - Random forest ensemble with 10 estimators
   - Feature importance tracking
   - Probability distribution output

4. **Anomaly Detector** (`AnomalyDetector`)
   - Isolation Forest algorithm
   - Detects code that deviates from normal patterns
   - Zero-day candidate identification

## 📁 Project Structure

```
oracle/
├── src/
│   ├── Oracle.jl           # Main module & exports
│   ├── analyzers/
│   │   ├── static.jl       # Static analysis engine
│   │   ├── semantic.jl     # Semantic analysis
│   │   ├── dataflow.jl     # Data flow analysis
│   │   ├── controlflow.jl  # Control flow analysis
│   │   └── taint.jl        # Taint tracking
│   ├── ml/
│   │   ├── embeddings.jl   # Code embeddings
│   │   ├── predictor.jl    # Vulnerability prediction
│   │   ├── classifier.jl   # Pattern classification
│   │   └── anomaly.jl      # Anomaly detection
│   ├── patterns/
│   │   ├── database.jl     # Pattern database
│   │   └── matcher.jl      # Pattern matching
│   ├── engine/
│   │   ├── scanner.jl      # Main scanner
│   │   └── risk.jl         # Risk calculation
│   ├── reporting/
│   │   └── generator.jl    # Report generation
│   ├── integrations/
│   │   ├── nvd.jl          # NVD API integration
│   │   └── cve.jl          # CVE tracking
│   └── utils/
│       ├── helpers.jl      # Utility functions
│       └── languages.jl    # Language support
├── test/
├── docs/
├── Project.toml
└── README.md
```

## 🎯 Supported Languages

| Language | Static | Semantic | Data Flow | Taint |
|----------|--------|----------|-----------|-------|
| C/C++    | ✅     | ✅       | ✅        | ✅    |
| Java     | ✅     | ✅       | ✅        | ✅    |
| Python   | ✅     | ✅       | ✅        | ✅    |
| JavaScript/TypeScript | ✅ | ✅ | ✅      | ✅    |
| PHP      | ✅     | ✅       | ✅        | ✅    |
| Go       | ✅     | ✅       | ✅        | ✅    |
| Rust     | ✅     | ✅       | ✅        | ✅    |
| Ruby     | ✅     | ✅       | ✅        | ✅    |

## 🔧 Configuration

### Scan Configuration

```julia
config = ScanConfig(
    # Scope
    include_patterns = ["*.c", "*.py", "*.js"],
    exclude_patterns = ["*test*", "*vendor*"],
    max_file_size = 1_000_000,
    # Analysis modules
    enable_static = true,
    enable_semantic = true,
    enable_dataflow = true,
    enable_taint = true,
    enable_ml = true,
    enable_anomaly = true,
    # Thresholds
    min_confidence = 0.5,
    max_findings_per_file = 50,
    # Performance
    parallel = true,
    max_workers = 8,
    timeout_seconds = 60,
    # Output
    verbose = false,
    generate_report = true,
    report_format = "html"
)
```

### Environment Variables

```bash
export NVD_API_KEY="your-api-key"      # For NVD integration
export ORACLE_CACHE_DIR="~/.oracle"    # Cache directory
export ORACLE_LOG_LEVEL="info"         # Logging level
```

## 📈 Performance

| Metric | Value |
|--------|-------|
| Files/second | ~100 (parallel) |
| Memory usage | ~500MB baseline |
| Prediction latency | <50ms |
| Accuracy (F1) | 0.87 (on benchmark) |

## 🔬 Training Custom Models

```julia
using Oracle

# Load training data
df = CSV.read("vulnerability_dataset.csv", DataFrame)

# Extract features and labels
features = extract_training_features(df)
labels = df.vuln_class

# Train predictor
predictor = VulnerabilityPredictor()
train!(predictor, features, labels, epochs=100)

# Save model
save_predictor(predictor, "custom_model.jls")

# Train classifier
classifier = PatternClassifier(n_estimators=50)
train!(classifier, features, labels)
save_classifier(classifier, "custom_classifier.jls")

# Train anomaly detector
detector = AnomalyDetector(contamination=0.05)
train!(detector, features)
save_detector(detector, "custom_detector.jls")
```

## 🤝 Integration

### CI/CD (GitHub Actions)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  oracle-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: julia-actions/setup-julia@v1
      - run: julia -e 'using Pkg; Pkg.add(url="https://github.com/yourusername/oracle")'
      - run: |
          julia -e '
            using Oracle
            result = scan_codebase(".")
            generate_report(result, format="sarif", output_file="results.sarif")
            exit(result.stats.findings_by_severity[CRITICAL] > 0 ? 1 : 0)
          '
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### IDE Integration (VS Code)

```json
{
  "oracle.enable": true,
  "oracle.onSave": true,
  "oracle.minSeverity": "medium",
  "oracle.enableML": true
}
```

## 📚 API Reference

### Core Functions

```julia
# Analyze a single file
analyze(filepath::String; language=nothing) -> AnalysisResult

# Scan entire codebase
scan_codebase(path::String; config=DEFAULT_SCAN_CONFIG) -> ScanResult

# Predict vulnerabilities
predict_vulnerabilities(code::String, language::String) -> Vector{PredictionResult}

# Generate report
generate_report(result::ScanResult; format="html") -> String
```

### Advanced Functions

```julia
# Create custom scanner
Scanner(; config::ScanConfig) -> Scanner

# Risk calculation
calculate_risk(calc::RiskCalculator, finding::Finding) -> Float64
calculate_cvss(finding::Finding) -> CVSSScore

# CVE correlation
correlate_findings(client::NVDClient, findings::Vector{Finding}) -> Vector{CorrelatedFinding}

# Anomaly analysis
analyze_anomaly(detector::AnomalyDetector, x::Vector, ref::Matrix) -> AnomalyAnalysis
```

## 🛡️ Security

Oracle is designed with security in mind:
- No code execution during analysis
- Sandboxed pattern matching
- Rate-limited external API calls
- Secure credential handling

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- NVD/NIST for vulnerability data
- CWE/MITRE for weakness enumeration
- The Julia community for excellent packages

---

<div align="center">

**[Documentation](docs/)** • **[Issues](issues/)** • **[Discussions](discussions/)**

Made with 💜 by the NullSec Team

</div>
