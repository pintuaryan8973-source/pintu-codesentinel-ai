<div align="center">

<img src="assets/codesentinel-banner.png" width="100%" alt="CodeSentinel AI Banner">

<br>

# 🛡️ CodeSentinel AI

### Intelligent Code Review & Security Analysis Assistant

**Detect • Analyze • Improve • Secure**

<br>

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Code Review](https://img.shields.io/badge/Code%20Review-Supported-8A2BE2)
![Security](https://img.shields.io/badge/Security-Analysis-00C853)
![Git](https://img.shields.io/badge/Git-Diff%20Review-F05032?logo=git&logoColor=white)
![Reports](https://img.shields.io/badge/Reports-HTML%20%7C%20JSON%20%7C%20Markdown-00B8D4)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-success)
![Status](https://img.shields.io/badge/Status-Active-success)
![Portfolio](https://img.shields.io/badge/Portfolio-Project-blueviolet)

<br>

**Python • JavaScript • TypeScript**

<br>

> Better Code. Safer Tomorrow.

</div>

---

# 🚀 What is CodeSentinel AI?

**CodeSentinel AI** is a developer-focused code review and security analysis CLI tool designed to simulate a professional software-development code review workflow.

It scans source code and identifies common:

- Programming bugs
- Security risks
- Reliability issues
- Maintainability problems
- Unsafe coding patterns
- Code quality problems

CodeSentinel AI reports findings with **file and line-level precision**.

For every detected issue, the tool can provide:

- Exact file name
- Exact line number
- Severity level
- Issue category
- Explanation
- Recommended fix
- Structured review reports

The tool can review an entire project or analyze only files changed between Git revisions.

---

# 💼 Real-World Scenario

Imagine a software company where a senior developer assigns a task to a junior developer:

> "Review this project before deployment. Find bugs, security issues and risky code, then provide a professional report."

Instead of manually checking every source file, the developer runs:

```bash
python reviewer.py scan project_folder
```

CodeSentinel AI scans the project and generates structured findings.

Example workflow:

```text
Senior Developer Assigns Project
            ↓
Developer Runs CodeSentinel AI
            ↓
Project Source Files Are Scanned
            ↓
Bug & Security Rules Analyze Code
            ↓
Exact File + Line Findings Generated
            ↓
Developer Reviews Recommended Fixes
            ↓
HTML / Markdown / JSON Reports Generated
            ↓
Code Is Improved Before Deployment
```

---

# ✨ Key Features

| Feature | Description |
|---|---|
| 🐞 Bug Detection | Detects common programming defects and runtime risks |
| 🛡️ Security Analysis | Identifies risky and potentially insecure patterns |
| 📁 Full Project Scan | Reviews complete project directories |
| 📍 Line-Level Review | Reports exact file and line number |
| 🚦 Severity Analysis | Critical, High, Medium and Low severity |
| 🏷️ Issue Categories | Bug, Security, Reliability, Maintainability and Style |
| 💡 Fix Suggestions | Provides recommended improvements |
| 🔀 Git Diff Review | Reviews files changed between Git revisions |
| 🆚 Visual Diff | Original vs Recommended code comparison |
| 📄 HTML Reports | Professional browser-based reports |
| 📝 Markdown Reports | GitHub-friendly review documentation |
| 🔧 JSON Reports | Structured output for automation |
| 📊 Benchmarking | Precision, Recall, F1 and review time |
| 💻 Multi-Language | Python, JavaScript and TypeScript |
| ⚡ Fast Static Analysis | Works locally without external Python packages |

---

# 🧠 Supported Code Review Checks

## Python

CodeSentinel AI currently checks for patterns including:

```text
Python Syntax Errors
Mutable Default Arguments
Bare except Blocks
eval() / exec()
os.system()
subprocess shell=True
Disabled TLS Verification
Literal Division by Zero
== None / != None
Possible Hard-Coded Secrets
Trailing Whitespace
```

Example:

```python
def add_user(name, users=[]):
    users.append(name)
    return users
```

CodeSentinel AI reports:

```text
HIGH | BUG | PY001

File       : buggy_app.py
Line       : 6
Issue      : Mutable default argument

Why:
Mutable default values are shared between function calls
and can cause unexpected state leakage.

Suggestion:
Use None as the default and create the list inside the function.
```

---

## JavaScript / TypeScript

Current checks include:

```text
eval()
Direct innerHTML Assignment
Shell Command Execution
document.write()
Possible Hard-Coded Secrets
```

Example:

```javascript
document.getElementById("output").innerHTML = message;
```

Possible finding:

```text
MEDIUM | SECURITY | JS002

Issue:
Direct innerHTML assignment

Why:
Untrusted content may introduce cross-site scripting risk.

Suggestion:
Prefer textContent or sanitize trusted HTML.
```

---

# 🚦 Severity Levels

| Severity | Meaning |
|---|---|
| 🔴 CRITICAL | Issue can directly break execution or create serious risk |
| 🟠 HIGH | Important security or correctness issue |
| 🟡 MEDIUM | Reliability or moderate security concern |
| 🔵 LOW | Maintainability, style or lower-risk problem |
| ⚪ INFO | Informational recommendation |

---

# ⚡ Quick Start

## 1. Open the Project

Open the `codesentinel-ai` folder in VS Code.

---

## 2. Scan the Included Sample Project

Run:

```bash
python reviewer.py scan sample_project
```

Example output:

```text
======================================================================================
                          CODESENTINEL AI
======================================================================================

Files reviewed : 2
Findings       : 11
Review time    : 0.002s

[1] CRITICAL | BUG | PY007

File       : buggy_app.py
Line       : 23
Issue      : Division or modulo by zero

Why:
This expression will raise a runtime exception.

Suggestion:
Validate the divisor or replace the zero with
the intended non-zero value.
```

---

# 📁 Scan Your Own Project

You can scan another project by passing its path.

Example:

```bash
python reviewer.py scan "C:\Users\pintu\Desktop\my-python-project"
```

Or:

```bash
python reviewer.py scan my_project
```

CodeSentinel AI recursively scans supported source files inside that project.

---

# 🔀 Git Diff Review

CodeSentinel AI can review only files changed between Git revisions.

Run:

```bash
python reviewer.py review --base HEAD~1 --target HEAD
```

Workflow:

```text
Previous Commit
      ↓
Git Diff
      ↓
Changed Source Files
      ↓
CodeSentinel AI Review
      ↓
Line-Level Findings
```

This is useful before:

```text
Git Commit
Pull Request
Code Merge
Deployment
Release
```

---

# 🆚 Original vs Recommended Code

CodeSentinel AI generates a visual side-by-side code comparison for supported safe transformations.

Example:

| Original | Recommended |
|---|---|
| `if user == None:` | `if user is None:` |
| Trailing spaces | Clean code |
| Unsafe style | Recommended style |

Example:

```text
ORIGINAL CODE                  RECOMMENDED CODE

if user == None:               if user is None:
    return False                   return False
```

The visual HTML report highlights changes so developers can quickly understand recommended improvements.

---

# 📊 Professional Reports

Every successful review can generate:

```text
reports/
├── review_report.html
├── review_report.md
└── review_report.json
```

## HTML Report

The HTML report provides:

```text
Files Reviewed
Total Findings
Critical Issues
High Issues
Medium Issues
Review Time
Detailed Findings
Original vs Recommended Diff
```

Open on Windows:

```powershell
start .\reports\review_report.html
```

Linux:

```bash
xdg-open reports/review_report.html
```

macOS:

```bash
open reports/review_report.html
```

---

## Markdown Report

Generated file:

```text
reports/review_report.md
```

Useful for:

```text
GitHub Documentation
Pull Request Notes
Code Review Evidence
Portfolio Documentation
Technical Reports
```

---

## JSON Report

Generated file:

```text
reports/review_report.json
```

Useful for future:

```text
Automation
Dashboards
CI/CD
APIs
Security Monitoring
Analytics
```

---

# 📊 Code Review Benchmark

CodeSentinel AI includes a small reproducible local benchmark.

Run:

```bash
python benchmark.py
```

Example output with the bundled labeled test cases:

```text
==============================================================
               LOCAL CODE REVIEW BENCHMARK
==============================================================

Precision : 100.00%
Recall    : 100.00%
F1 Score  : 100.00%
Avg Time  : 0.000693s

TP / FP / FN : 6 / 0 / 0

==============================================================
```

---

# 📈 Benchmark Metrics

| Metric | What it Measures | Why it Matters |
|---|---|---|
| F1 Score | Harmonic mean of Precision and Recall | Overall detection quality |
| Precision | How many reported issues were expected findings | Fewer false alarms |
| Recall | How many expected issues were detected | Fewer missed issues |
| Avg Time | Average review execution time | Performance |
| True Positive | Correctly detected issue | Correct detection |
| False Positive | Unexpected reported issue | False alert |
| False Negative | Expected issue not detected | Missed issue |

---

# ⚠️ Benchmark Disclaimer

The included benchmark measures only the **small labeled test cases provided inside this repository**.

A result such as:

```text
Precision : 100%
Recall    : 100%
F1 Score  : 100%
```

does **not** mean CodeSentinel AI has 100% accuracy on real-world software projects.

The benchmark exists to demonstrate how code-review quality can be measured using reproducible test cases.

---

# 📂 Project Structure

```text
codesentinel-ai/
│
├── assets/
│   └── codesentinel-banner.png
│
├── reviewer.py
├── benchmark.py
├── README.md
│
├── sample_project/
│   ├── buggy_app.py
│   └── unsafe_web.js
│
├── benchmark_cases/
│   ├── case_python.py
│   └── case_web.js
│
└── reports/
    ├── review_report.html
    ├── review_report.md
    ├── review_report.json
    └── benchmark.json
```

---

# 🧪 Sample Project

The repository contains intentionally vulnerable or buggy sample files.

These files exist only to demonstrate CodeSentinel AI's detection capabilities.

Example:

```python
def average(total, count):
    return total / 0
```

Finding:

```text
CRITICAL | BUG | PY007

Issue:
Division or modulo by zero

Suggestion:
Validate the divisor before performing the operation.
```

---

# 🔐 Security Analysis Example

Example unsafe code:

```python
os.system("backup " + filename)
```

Possible report:

```text
HIGH | SECURITY | PY004

Issue:
os.system() command execution

Why:
Building shell commands from untrusted data can
lead to command injection.

Suggestion:
Prefer subprocess.run([...], shell=False)
and validate arguments.
```

---

# 🔑 Hard-Coded Secret Detection

Example:

```python
API_KEY = "demo-secret-key-123456"
```

CodeSentinel AI can report:

```text
HIGH | SECURITY | GEN001

Issue:
Possible hard-coded secret

Suggestion:
Move secrets to environment variables or
a secret manager.
```

> The sample secrets included in this repository are fake demonstration values only.

---

# 🖥️ Supported Platforms

| Platform | Status |
|---|---|
| Windows | ✅ Supported |
| Linux | ✅ Supported |
| macOS | ✅ Supported |

---

# 💻 Supported Languages

| Language | Current Support |
|---|---|
| Python | ✅ |
| JavaScript | ✅ |
| TypeScript | ✅ |
| JSX | ✅ |
| TSX | ✅ |
| Java | 🔜 Planned |
| Go | 🔜 Planned |
| C / C++ | 🔜 Planned |

---

# 📸 Portfolio Screenshots

Recommended screenshots for this repository:

```text
01-terminal-review.png
02-visual-diff-report.png
03-benchmark.png
04-project-code.png
```

## Screenshot 1 — Terminal Review

Show:

```text
Files Reviewed
Findings
Severity
File
Line
Issue
Suggestion
```

---

## Screenshot 2 — Visual Diff Report

Show the browser HTML report containing:

```text
Original Code
Recommended Code
Findings
Severity
Review Statistics
```

---

## Screenshot 3 — Benchmark

Run:

```bash
python benchmark.py
```

Capture:

```text
Precision
Recall
F1 Score
Avg Time
TP / FP / FN
```

---

## Screenshot 4 — Project Code

Open `reviewer.py` in VS Code.

Keep Explorer visible showing:

```text
assets
benchmark_cases
sample_project
reports
reviewer.py
benchmark.py
README.md
```

---

# 🛠️ Technologies Used

```text
Python 3
Python AST
Regular Expressions
Git
Git Diff
HTML
CSS
JSON
Markdown
CLI
Static Code Analysis
Security Analysis
Benchmarking
```

---

# 🧩 How It Works

```text
                   ┌──────────────────────┐
                   │   Source Project     │
                   └──────────┬───────────┘
                              │
                              ▼
                   ┌──────────────────────┐
                   │ File Discovery       │
                   │ Python / JS / TS     │
                   └──────────┬───────────┘
                              │
                              ▼
                   ┌──────────────────────┐
                   │ Static Analysis      │
                   │ AST + Rules          │
                   └──────────┬───────────┘
                              │
                              ▼
                   ┌──────────────────────┐
                   │ Security Analysis    │
                   │ Risky Patterns       │
                   └──────────┬───────────┘
                              │
                              ▼
                   ┌──────────────────────┐
                   │ Finding Engine       │
                   │ File + Line + Risk   │
                   └──────────┬───────────┘
                              │
                              ▼
             ┌────────────────────────────────┐
             │ HTML | Markdown | JSON Report │
             └────────────────────────────────┘
```

---

# 🎯 Learning Outcomes

This project demonstrates practical knowledge of:

```text
Python Programming
Static Code Analysis
Abstract Syntax Trees
Security Analysis
Git Workflow
Software Debugging
Code Review
Report Generation
Benchmarking
CLI Application Development
Defensive Programming
GitHub Project Documentation
```

---

# 🚀 Future Improvements

Future versions may include:

```text
Optional LLM-Based Deep Code Review
More Programming Languages
Pull Request Integration
GitHub Actions
CI/CD Integration
Automatic Safe Fix Application
Custom Rule Configuration
Rule Enable / Disable Options
Interactive Dashboard
PDF Reports
SARIF Output
Repository-Level Context
Duplicate Finding Reduction
Advanced Security Rules
Test Execution Integration
Review History
Team Dashboard
```

---

# 🤖 AI Integration Roadmap

The current version primarily uses deterministic static-analysis rules.

A future AI layer can be added to analyze:

```text
Business Logic
Complex Code Context
Cross-File Relationships
Maintainability
Architecture
Developer Intent
More Advanced Bug Patterns
```

This approach keeps the current results reproducible while leaving room for advanced AI-assisted reviews.

---

# ⚖️ Important Limitations

CodeSentinel AI is a **code review assistant**.

It does not guarantee that:

```text
Every possible bug will be found
Every security vulnerability will be detected
Every suggestion is appropriate for every project
A reviewed project is automatically secure
```

Developers should always verify findings before modifying production code.

---

# 🔒 Security & Ethics

CodeSentinel AI is designed for:

```text
Software Development
Defensive Security
Educational Labs
Authorized Code Review
Personal Projects
Company Projects You Are Authorized To Review
```

Do not use confidential source code with external services unless you have permission from the code owner.

---

# 🗺️ Roadmap

```text
✅ Full Project Scan
✅ Python Review
✅ JavaScript Review
✅ TypeScript Review
✅ File + Line Findings
✅ Severity Analysis
✅ Security Analysis
✅ Git Diff Review
✅ HTML Reports
✅ Markdown Reports
✅ JSON Reports
✅ Original vs Recommended Diff
✅ Local Benchmark

🔜 AI-Assisted Review
🔜 GitHub Actions
🔜 Pull Request Comments
🔜 More Languages
🔜 Automatic Safe Fixes
🔜 Dashboard
🔜 SARIF Support
```

---

# 📌 Why I Built This Project

Modern development teams perform code reviews before merging and deploying software.

I created CodeSentinel AI to understand and demonstrate:

```text
How code-review tools analyze source code
How bugs can be detected programmatically
How security rules can identify risky code
How Git-based review workflows work
How professional reports can be generated
How review quality can be benchmarked
```

The project was built as part of my practical learning journey in Python, Cyber Security and software development.

---

# 👨‍💻 Author

## Pintu Aryan

**Aspiring Cyber Security Analyst**

Networking | Python | Security Operations

GitHub:

```text
https://github.com/pintuaryan8973-source
```

---

<div align="center">

## 🛡️ CodeSentinel AI

### Detect • Analyze • Improve • Secure

**Better Code. Safer Tomorrow.**

⭐ If you find this project useful, consider starring the repository.

</div>