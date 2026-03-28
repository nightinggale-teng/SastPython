# SastPython

**Static Application Security Testing (SAST) Tool for Python**

SastPython is a command-line Static Application Security Testing (SAST) tool designed to analyze Python source code and dependency files. It performs AST-based analysis to detect common security vulnerabilities and misconfigurations based on OWASP categories and secure coding practices.

---

## ✨ Features

- Static analysis of Python (`.py`) files using Abstract Syntax Tree (AST)
- Detection of common vulnerabilities:
  - Injection
  - Cryptographic failures
  - Insecure deserialization
  - Security misconfiguration
  - Vulnerable or outdated dependencies
- Dependency file scanning (`requirements.txt`, `pyproject.toml`, etc.)
- Console summary and detailed reports
- Optional PDF report generation
- Simple CLI command (`SastPython`) after installation

---

## 📦 Installation

### Prerequisites

- Python **3.9 or later**
- `pip` installed
- Git installed

---

### 🔽 Install from GitHub

1. **Clone the repository**

```bash
git clone https://github.com/<username>/SastPython.git
cd SastPython
```

2. **(Optional but recommended) Create a virtual environment**

```bash
python -m venv .venv
```

Activate it:

- **Windows**
  ```bash
  .venv\Scripts\activate
  ```

- **Linux / macOS**
  ```bash
  source .venv/bin/activate
  ```

3. **Install the tool**

```bash
pip install -e .
```

> This installs SastPython in editable mode and registers the `SastPython` command globally for the active Python environment.

---

## ▶️ Usage

After installation, the tool can be run from **any terminal**.

### Basic scan

```bash
SastPython target.py
```

### Detailed output

```bash
SastPython target.py --detail
```

### Generate PDF report

```bash
SastPython target.py --detail --pdf report.pdf
```

### Scan dependency files

```bash
SastPython requirements.txt
```

---

## ⚙️ Command-Line Options

| Option | Description |
|------------------------|----------------------------------------|
| `target` | Path to Python file or dependency file |
| `--detail` | Show detailed vulnerability findings |
| `--pdf <filename>` | Export report to a PDF file |
| `--verbose` | Enable debug-level logging |
| `--max-bytes <size>` | Maximum file size to analyze |
| `--allow-system-paths` | Allow scanning system directories |
| `--help` | Show help message |

Example:

```bash
SastPython example.py --detail --verbose
```

---

## 📊 Output

- **Console Report**
  - Vulnerability summary by severity
  - Risk score
  - Actionable recommendations

- **PDF Report (optional)**
  - Executive summary
  - Vulnerability breakdown
  - Severity distribution
  - Detailed findings

---

## 🧪 Example

```bash
SastPython examples/test_report.py --detail --pdf examples/report.pdf
```

---

## 🛠 Project Structure

```
sastpython/
├── cli.py          # CLI entry point
├── core.py         # AST analyzer
├── reporter.py     # Console and PDF reporting
└── rules*.py       # Security detection rules
```

---

## 🔒 Disclaimer

This tool is intended for **educational and defensive security purposes only**. Results should be reviewed by developers or security professionals before applying fixes.

---

## 📚 License

This project is developed as part of an academic Final Year Project (FYP). License information can be added if the project is published publicly.

---

## 👤 Author

Developed by **LCT**

Static Application Security Testing for Python – Final Year Project

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the issues page if you want to contribute.

---

## 📧 Contact

For questions or feedback, please contact the author or open an issue on GitHub.