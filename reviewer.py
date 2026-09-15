from __future__ import annotations

import argparse
import ast
import difflib
import html
import json
import re
import subprocess
import time

from dataclasses import dataclass, asdict
from pathlib import Path


# ============================================================
# CODESENTINEL AI
# Intelligent Code Review & Security Analysis Assistant
# ============================================================


SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
}

IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    "reports",
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


# ============================================================
# FINDING MODEL
# ============================================================

@dataclass
class Finding:
    file: str
    line: int
    severity: str
    category: str
    rule: str
    title: str
    explanation: str
    suggestion: str


# ============================================================
# FILE DISCOVERY
# ============================================================

def collect_source_files(target: Path) -> list[Path]:

    if target.is_file():

        if target.suffix.lower() in SUPPORTED_EXTENSIONS:
            return [target]

        return []

    if not target.is_dir():
        return []

    files = []

    for path in target.rglob("*"):

        if not path.is_file():
            continue

        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue

        if any(
            part in IGNORED_DIRECTORIES
            for part in path.parts
        ):
            continue

        files.append(path)

    return sorted(files)


# ============================================================
# RELATIVE PATH
# ============================================================

def relative_path(
    path: Path,
    base: Path
) -> str:

    try:

        return (
            path.resolve()
            .relative_to(base.resolve())
            .as_posix()
        )

    except Exception:

        return path.as_posix()


# ============================================================
# COMMON SECURITY RULES
# ============================================================

SECRET_PATTERN = re.compile(
    r'(?i)\b'
    r'(api[_-]?key|secret|password|passwd|token)'
    r'\b\s*[:=]\s*'
    r'["\'][^"\']{6,}["\']'
)


def scan_common_text(
    path: Path,
    text: str
) -> list[Finding]:

    findings = []

    lines = text.splitlines()

    for number, line in enumerate(
        lines,
        start=1
    ):

        # ----------------------------------------------------
        # Hard-coded secret
        # ----------------------------------------------------

        if SECRET_PATTERN.search(line):

            findings.append(
                Finding(
                    file=str(path),
                    line=number,
                    severity="HIGH",
                    category="security",
                    rule="GEN001",
                    title="Possible hard-coded secret",
                    explanation=(
                        "Secrets stored directly in source code "
                        "may leak through Git history, logs "
                        "or screenshots."
                    ),
                    suggestion=(
                        "Move secrets to environment variables "
                        "or a secret manager and rotate any "
                        "exposed credentials."
                    ),
                )
            )

        # ----------------------------------------------------
        # Trailing whitespace
        # ----------------------------------------------------

        if line.rstrip() != line:

            findings.append(
                Finding(
                    file=str(path),
                    line=number,
                    severity="LOW",
                    category="style",
                    rule="GEN002",
                    title="Trailing whitespace",
                    explanation=(
                        "Trailing whitespace creates noisy "
                        "Git diffs and reduces code cleanliness."
                    ),
                    suggestion=(
                        "Remove trailing whitespace."
                    ),
                )
            )

    return findings


# ============================================================
# PYTHON ANALYSIS
# ============================================================

def scan_python(
    path: Path
) -> list[Finding]:

    findings = []

    try:

        text = path.read_text(
            encoding="utf-8"
        )

    except Exception:

        return findings

    findings.extend(
        scan_common_text(
            path,
            text
        )
    )

    try:

        tree = ast.parse(
            text,
            filename=str(path)
        )

    except SyntaxError as error:

        findings.append(
            Finding(
                file=str(path),
                line=error.lineno or 1,
                severity="CRITICAL",
                category="bug",
                rule="PY000",
                title="Python syntax error",
                explanation=error.msg,
                suggestion=(
                    "Fix the syntax error before "
                    "running or reviewing the program."
                ),
            )
        )

        return findings


    # ========================================================
    # AST RULES
    # ========================================================

    for node in ast.walk(tree):

        # ----------------------------------------------------
        # Mutable Default Argument
        # ----------------------------------------------------

        if isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef
            )
        ):

            defaults = (
                list(node.args.defaults)
                +
                [
                    item
                    for item
                    in node.args.kw_defaults
                    if item is not None
                ]
            )

            for default in defaults:

                if isinstance(
                    default,
                    (
                        ast.List,
                        ast.Dict,
                        ast.Set
                    )
                ):

                    findings.append(
                        Finding(
                            file=str(path),
                            line=default.lineno,
                            severity="HIGH",
                            category="bug",
                            rule="PY001",
                            title=(
                                "Mutable default argument"
                            ),
                            explanation=(
                                "Mutable default values are "
                                "shared between function calls "
                                "and can cause unexpected state."
                            ),
                            suggestion=(
                                "Use None as the default and "
                                "create the list, dictionary "
                                "or set inside the function."
                            ),
                        )
                    )


        # ----------------------------------------------------
        # Bare Except
        # ----------------------------------------------------

        if isinstance(
            node,
            ast.ExceptHandler
        ):

            if node.type is None:

                findings.append(
                    Finding(
                        file=str(path),
                        line=node.lineno,
                        severity="MEDIUM",
                        category="reliability",
                        rule="PY002",
                        title="Bare except block",
                        explanation=(
                            "A bare except catches every "
                            "exception, including errors that "
                            "should usually be visible."
                        ),
                        suggestion=(
                            "Catch only the specific "
                            "exception types you expect."
                        ),
                    )
                )


        # ----------------------------------------------------
        # Function Calls
        # ----------------------------------------------------

        if isinstance(
            node,
            ast.Call
        ):

            function_name = ""
            owner_name = ""

            if isinstance(
                node.func,
                ast.Name
            ):

                function_name = (
                    node.func.id
                )

            elif isinstance(
                node.func,
                ast.Attribute
            ):

                function_name = (
                    node.func.attr
                )

                if isinstance(
                    node.func.value,
                    ast.Name
                ):

                    owner_name = (
                        node.func.value.id
                    )


            # ------------------------------------------------
            # eval / exec
            # ------------------------------------------------

            if function_name in {
                "eval",
                "exec"
            }:

                findings.append(
                    Finding(
                        file=str(path),
                        line=node.lineno,
                        severity="HIGH",
                        category="security",
                        rule="PY003",
                        title=(
                            f"Use of "
                            f"{function_name}()"
                        ),
                        explanation=(
                            f"{function_name}() can execute "
                            "arbitrary code when input "
                            "is untrusted."
                        ),
                        suggestion=(
                            "Avoid dynamic code execution. "
                            "Parse and validate structured "
                            "input instead."
                        ),
                    )
                )


            # ------------------------------------------------
            # os.system
            # ------------------------------------------------

            if (
                owner_name == "os"
                and
                function_name == "system"
            ):

                findings.append(
                    Finding(
                        file=str(path),
                        line=node.lineno,
                        severity="HIGH",
                        category="security",
                        rule="PY004",
                        title=(
                            "os.system() command execution"
                        ),
                        explanation=(
                            "Building shell commands from "
                            "untrusted data may lead to "
                            "command injection."
                        ),
                        suggestion=(
                            "Prefer subprocess.run() with "
                            "an argument list and "
                            "shell=False."
                        ),
                    )
                )


            # ------------------------------------------------
            # Keyword arguments
            # ------------------------------------------------

            for keyword in node.keywords:

                # shell=True

                if (
                    keyword.arg == "shell"
                    and
                    isinstance(
                        keyword.value,
                        ast.Constant
                    )
                    and
                    keyword.value.value is True
                ):

                    findings.append(
                        Finding(
                            file=str(path),
                            line=node.lineno,
                            severity="HIGH",
                            category="security",
                            rule="PY005",
                            title=(
                                "subprocess shell=True"
                            ),
                            explanation=(
                                "shell=True increases "
                                "command-injection risk."
                            ),
                            suggestion=(
                                "Use shell=False and pass "
                                "command arguments as a list."
                            ),
                        )
                    )


                # verify=False

                if (
                    keyword.arg == "verify"
                    and
                    isinstance(
                        keyword.value,
                        ast.Constant
                    )
                    and
                    keyword.value.value is False
                ):

                    findings.append(
                        Finding(
                            file=str(path),
                            line=node.lineno,
                            severity="HIGH",
                            category="security",
                            rule="PY006",
                            title=(
                                "TLS verification disabled"
                            ),
                            explanation=(
                                "Disabling certificate "
                                "verification weakens "
                                "HTTPS security."
                            ),
                            suggestion=(
                                "Keep TLS certificate "
                                "verification enabled."
                            ),
                        )
                    )


        # ----------------------------------------------------
        # Division by zero
        # ----------------------------------------------------

        if (
            isinstance(
                node,
                ast.BinOp
            )
            and
            isinstance(
                node.op,
                (
                    ast.Div,
                    ast.FloorDiv,
                    ast.Mod
                )
            )
        ):

            if (
                isinstance(
                    node.right,
                    ast.Constant
                )
                and
                node.right.value == 0
            ):

                findings.append(
                    Finding(
                        file=str(path),
                        line=node.lineno,
                        severity="CRITICAL",
                        category="bug",
                        rule="PY007",
                        title=(
                            "Division or modulo by zero"
                        ),
                        explanation=(
                            "This expression will raise "
                            "a runtime exception."
                        ),
                        suggestion=(
                            "Validate the divisor before "
                            "performing the operation."
                        ),
                    )
                )


        # ----------------------------------------------------
        # None comparison
        # ----------------------------------------------------

        if isinstance(
            node,
            ast.Compare
        ):

            values = (
                [node.left]
                +
                list(node.comparators)
            )

            contains_none = any(

                isinstance(
                    value,
                    ast.Constant
                )
                and
                value.value is None

                for value in values
            )

            if contains_none:

                uses_eq = any(

                    isinstance(
                        operator,
                        (
                            ast.Eq,
                            ast.NotEq
                        )
                    )

                    for operator
                    in node.ops
                )

                if uses_eq:

                    findings.append(
                        Finding(
                            file=str(path),
                            line=node.lineno,
                            severity="LOW",
                            category=(
                                "maintainability"
                            ),
                            rule="PY008",
                            title=(
                                "None compared with "
                                "== or !="
                            ),
                            explanation=(
                                "Python convention uses "
                                "identity checks when "
                                "comparing with None."
                            ),
                            suggestion=(
                                "Use 'is None' or "
                                "'is not None'."
                            ),
                        )
                    )

    return findings


# ============================================================
# JAVASCRIPT / TYPESCRIPT ANALYSIS
# ============================================================

def scan_javascript(
    path: Path
) -> list[Finding]:

    findings = []

    try:

        text = path.read_text(
            encoding="utf-8"
        )

    except Exception:

        return findings

    findings.extend(
        scan_common_text(
            path,
            text
        )
    )


    rules = [

        (
            r"\beval\s*\(",
            "HIGH",
            "security",
            "JS001",
            "Use of eval()",
            (
                "eval() may execute "
                "attacker-controlled JavaScript."
            ),
            (
                "Avoid eval() and validate "
                "structured input instead."
            ),
        ),

        (
            r"\.innerHTML\s*=",
            "MEDIUM",
            "security",
            "JS002",
            "Direct innerHTML assignment",
            (
                "Untrusted HTML content may "
                "lead to cross-site scripting."
            ),
            (
                "Prefer textContent or "
                "sanitize trusted HTML."
            ),
        ),

        (
            r"\b(child_process\.)?"
            r"exec\s*\(",
            "HIGH",
            "security",
            "JS003",
            "Shell command execution",
            (
                "Shell command construction "
                "may create command injection."
            ),
            (
                "Prefer execFile or spawn "
                "with argument arrays."
            ),
        ),

        (
            r"\bdocument\.write\s*\(",
            "MEDIUM",
            "maintainability",
            "JS004",
            "document.write() usage",
            (
                "document.write() creates "
                "unsafe and difficult-to-"
                "maintain DOM behavior."
            ),
            (
                "Use modern DOM APIs instead."
            ),
        ),

    ]


    for number, line in enumerate(
        text.splitlines(),
        start=1
    ):

        for (
            pattern,
            severity,
            category,
            rule,
            title,
            explanation,
            suggestion
        ) in rules:

            if re.search(
                pattern,
                line
            ):

                findings.append(
                    Finding(
                        file=str(path),
                        line=number,
                        severity=severity,
                        category=category,
                        rule=rule,
                        title=title,
                        explanation=explanation,
                        suggestion=suggestion,
                    )
                )

    return findings


# ============================================================
# SCAN FILE
# ============================================================

def scan_file(
    path: Path
) -> list[Finding]:

    extension = path.suffix.lower()

    if extension == ".py":

        return scan_python(path)

    if extension in {
        ".js",
        ".jsx",
        ".ts",
        ".tsx"
    }:

        return scan_javascript(path)

    return []


# ============================================================
# SAFE RECOMMENDED CODE
# ============================================================

def generate_recommended_code(
    text: str
) -> str:

    fixed = text

    # Remove trailing whitespace

    fixed = "\n".join(
        line.rstrip()
        for line
        in fixed.splitlines()
    )

    if text.endswith("\n"):
        fixed += "\n"


    # Replace == None

    fixed = re.sub(
        r"\b([A-Za-z_]\w*)"
        r"\s*==\s*None\b",
        r"\1 is None",
        fixed
    )


    # Replace != None

    fixed = re.sub(
        r"\b([A-Za-z_]\w*)"
        r"\s*!=\s*None\b",
        r"\1 is not None",
        fixed
    )

    return fixed


# ============================================================
# GIT DIFF REVIEW
# ============================================================

def changed_git_files(
    base_ref: str,
    target_ref: str
) -> list[Path]:

    result = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            f"{base_ref}...{target_ref}"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:

        raise RuntimeError(
            result.stderr.strip()
            or
            "Git diff failed."
        )

    files = []

    for name in result.stdout.splitlines():

        path = Path(name)

        if (
            path.exists()
            and
            path.suffix.lower()
            in SUPPORTED_EXTENSIONS
        ):

            files.append(path)

    return files


# ============================================================
# NORMALIZE PATHS
# ============================================================

def normalize_findings(
    findings: list[Finding],
    base: Path
) -> list[Finding]:

    for finding in findings:

        finding.file = relative_path(
            Path(finding.file),
            base
        )

    return findings


# ============================================================
# REMOVE DUPLICATES
# ============================================================

def deduplicate_findings(
    findings: list[Finding]
) -> list[Finding]:

    seen = set()

    cleaned = []

    for finding in findings:

        key = (
            finding.file,
            finding.line,
            finding.rule
        )

        if key in seen:
            continue

        seen.add(key)

        cleaned.append(finding)


    return sorted(

        cleaned,

        key=lambda finding: (

            SEVERITY_ORDER.get(
                finding.severity,
                99
            ),

            finding.file,

            finding.line,

            finding.rule
        )
    )


# ============================================================
# TERMINAL REPORT
# ============================================================

def print_terminal_report(
    findings: list[Finding],
    files_count: int,
    elapsed: float
) -> None:

    print()

    print(
        "=" * 88
    )

    print(
        "                              CODESENTINEL AI"
    )

    print(
        "=" * 88
    )

    print(
        "AI-Powered Code Review "
        "& Security Analysis Assistant"
    )

    print()

    print(
        f"Files reviewed : "
        f"{files_count}"
    )

    print(
        f"Findings       : "
        f"{len(findings)}"
    )

    print(
        f"Review time    : "
        f"{elapsed:.4f}s"
    )


    if not findings:

        print()

        print(
            "[OK] No supported issues found."
        )

        return


    for index, finding in enumerate(
        findings,
        start=1
    ):

        print()

        print(
            f"[{index}] "
            f"{finding.severity} | "
            f"{finding.category.upper()} | "
            f"{finding.rule}"
        )

        print(
            f"File       : "
            f"{finding.file}"
        )

        print(
            f"Line       : "
            f"{finding.line}"
        )

        print(
            f"Issue      : "
            f"{finding.title}"
        )

        print(
            f"Why        : "
            f"{finding.explanation}"
        )

        print(
            f"Suggestion : "
            f"{finding.suggestion}"
        )


    print()

    print(
        "=" * 88
    )


# ============================================================
# HTML REPORT
# ============================================================

def create_html_report(
    findings: list[Finding],
    files: list[Path],
    base: Path,
    elapsed: float,
    report_directory: Path
) -> None:

    report_directory.mkdir(
        parents=True,
        exist_ok=True
    )


    # ========================================================
    # COUNTS
    # ========================================================

    critical_count = sum(
        1
        for finding
        in findings
        if finding.severity
        == "CRITICAL"
    )

    high_count = sum(
        1
        for finding
        in findings
        if finding.severity
        == "HIGH"
    )

    medium_count = sum(
        1
        for finding
        in findings
        if finding.severity
        == "MEDIUM"
    )

    low_count = sum(
        1
        for finding
        in findings
        if finding.severity
        == "LOW"
    )


    # ========================================================
    # FINDING TABLE
    # ========================================================

    finding_rows = []

    for finding in findings:

        finding_rows.append(
            f"""
            <tr>

                <td>
                    <span class="
                        severity
                        {finding.severity.lower()}
                    ">
                        {html.escape(
                            finding.severity
                        )}
                    </span>
                </td>

                <td>
                    {html.escape(
                        finding.file
                    )}
                </td>

                <td>
                    {finding.line}
                </td>

                <td>
                    {html.escape(
                        finding.category
                    )}
                </td>

                <td>
                    {html.escape(
                        finding.title
                    )}
                </td>

                <td>
                    {html.escape(
                        finding.suggestion
                    )}
                </td>

            </tr>
            """
        )


    # ========================================================
    # SIDE-BY-SIDE DIFF
    # ========================================================

    diff_sections = []

    for source_file in files:

        try:

            original_text = (
                source_file
                .read_text(
                    encoding="utf-8"
                )
            )

        except Exception:

            continue


        recommended_text = (
            generate_recommended_code(
                original_text
            )
        )


        if (
            original_text
            ==
            recommended_text
        ):

            continue


        original_lines = (
            original_text
            .splitlines()
        )

        recommended_lines = (
            recommended_text
            .splitlines()
        )


        matcher = (
            difflib
            .SequenceMatcher(
                a=original_lines,
                b=recommended_lines
            )
        )


        diff_rows = []


        for (
            tag,
            i1,
            i2,
            j1,
            j2
        ) in matcher.get_opcodes():

            maximum = max(
                i2 - i1,
                j2 - j1
            )


            for index in range(
                maximum
            ):

                original_line = ""

                recommended_line = ""

                original_number = ""

                recommended_number = ""


                if (
                    i1 + index
                    <
                    i2
                ):

                    original_line = (
                        original_lines[
                            i1 + index
                        ]
                    )

                    original_number = (
                        str(
                            i1
                            + index
                            + 1
                        )
                    )


                if (
                    j1 + index
                    <
                    j2
                ):

                    recommended_line = (
                        recommended_lines[
                            j1 + index
                        ]
                    )

                    recommended_number = (
                        str(
                            j1
                            + index
                            + 1
                        )
                    )


                left_class = "same"

                right_class = "same"


                if tag in {
                    "replace",
                    "delete"
                }:

                    if original_line:

                        left_class = (
                            "removed"
                        )


                if tag in {
                    "replace",
                    "insert"
                }:

                    if recommended_line:

                        right_class = (
                            "added"
                        )


                diff_rows.append(
                    f"""
                    <div class="diff-row">

                        <div class="
                            code-line
                            {left_class}
                        ">

                            <span class="line-number">
                                {original_number}
                            </span>

                            <code>
                                {html.escape(
                                    original_line
                                )}
                            </code>

                        </div>


                        <div class="
                            code-line
                            {right_class}
                        ">

                            <span class="line-number">
                                {recommended_number}
                            </span>

                            <code>
                                {html.escape(
                                    recommended_line
                                )}
                            </code>

                        </div>

                    </div>
                    """
                )


        diff_sections.append(
            f"""
            <section class="diff-card">

                <div class="diff-title">

                    Suggested Safe Fixes —

                    {
                        html.escape(
                            relative_path(
                                source_file,
                                base
                            )
                        )
                    }

                </div>


                <div class="diff-header">

                    <div>
                        Original Code
                    </div>

                    <div>
                        Recommended Code
                    </div>

                </div>


                {
                    "".join(
                        diff_rows
                    )
                }

            </section>
            """
        )


    # ========================================================
    # FULL HTML
    # ========================================================

    document = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
CodeSentinel AI - Code Review Report
</title>


<style>

* {{
    box-sizing: border-box;
}}


body {{

    margin: 0;

    background:

        radial-gradient(
            circle at top left,
            rgba(0, 255, 204, 0.08),
            transparent 25%
        ),

        #080d18;

    color: #eaf0ff;

    font-family:
        Arial,
        Helvetica,
        sans-serif;
}}


.container {{

    width: 94%;

    max-width: 1500px;

    margin: auto;

    padding:
        35px 20px 80px;
}}


/* ======================================================
   BRANDING
====================================================== */

.brand-banner {{

    width: 100%;

    margin-bottom: 25px;

    text-align: center;
}}


.brand-banner img {{

    width: 100%;

    max-width: 1200px;

    border-radius: 20px;

    border:
        1px solid
        rgba(
            0,
            255,
            204,
            0.25
        );

    box-shadow:
        0 0 40px
        rgba(
            0,
            255,
            204,
            0.08
        );
}}


h1 {{

    text-align: center;

    color: #5fffe1;

    margin-bottom: 8px;

    font-size: 42px;
}}


.subtitle {{

    text-align: center;

    color: #95a6c7;

    margin-bottom: 35px;

    font-size: 17px;
}}


/* ======================================================
   STAT CARDS
====================================================== */

.stats {{

    display: grid;

    grid-template-columns:
        repeat(
            6,
            1fr
        );

    gap: 14px;

    margin-bottom: 35px;
}}


.stat-card {{

    background:
        linear-gradient(
            145deg,
            #111a2c,
            #0d1525
        );

    border:
        1px solid
        #263859;

    border-radius: 15px;

    padding: 18px;

    text-align: center;
}}


.stat-card span {{

    color: #8ea0c0;

    display: block;

    font-size: 13px;
}}


.stat-card b {{

    display: block;

    margin-top: 8px;

    font-size: 28px;

    color: white;
}}


/* ======================================================
   SECTION TITLE
====================================================== */

.section-title {{

    margin:
        40px 0 16px;

    font-size: 23px;

    color: #5fffe1;
}}


/* ======================================================
   TABLE
====================================================== */

.table-wrapper {{

    overflow-x: auto;

    border-radius: 15px;

    border:
        1px solid #263859;
}}


table {{

    width: 100%;

    border-collapse: collapse;

    background: #101827;
}}


th,
td {{

    padding: 13px;

    text-align: left;

    vertical-align: top;

    border-bottom:
        1px solid #263859;
}}


th {{

    background: #0d1525;

    color: #5fffe1;
}}


/* ======================================================
   SEVERITY COLORS
====================================================== */

.severity {{

    font-weight: bold;
}}


.critical {{

    color: #ff5c70;
}}


.high {{

    color: #ff9f43;
}}


.medium {{

    color: #ffd166;
}}


.low {{

    color: #74dfff;
}}


.info {{

    color: #a8dadc;
}}


/* ======================================================
   DIFF VIEW
====================================================== */

.diff-card {{

    margin-top: 25px;

    background: #101827;

    border:
        1px solid #263859;

    border-radius: 15px;

    overflow: hidden;
}}


.diff-title {{

    padding: 16px 20px;

    color: #5fffe1;

    font-weight: bold;

    border-bottom:
        1px solid #263859;
}}


.diff-header {{

    display: grid;

    grid-template-columns:
        1fr 1fr;

    background: #0d1525;
}}


.diff-header div {{

    padding: 12px 16px;

    color: #9cb0d2;

    border-right:
        1px solid #263859;

    font-weight: bold;
}}


.diff-row {{

    display: grid;

    grid-template-columns:
        1fr 1fr;
}}


.code-line {{

    display: grid;

    grid-template-columns:
        55px 1fr;

    min-height: 32px;

    border-right:
        1px solid #263859;

    border-bottom:
        1px solid
        rgba(
            38,
            56,
            89,
            0.45
        );
}}


.line-number {{

    padding: 7px 10px;

    color: #7184a8;

    text-align: right;

    border-right:
        1px solid #263859;
}}


.code-line code {{

    padding: 7px 12px;

    white-space: pre-wrap;

    font-family:
        Consolas,
        monospace;

    color: #e7edf9;
}}


.removed {{

    background:
        rgba(
            255,
            70,
            90,
            0.18
        );
}}


.added {{

    background:
        rgba(
            40,
            200,
            120,
            0.18
        );
}}


.same {{

    background: #101827;
}}


/* ======================================================
   FOOTER
====================================================== */

.footer {{

    margin-top: 55px;

    text-align: center;

    color: #7282a2;

    font-size: 14px;
}}


.footer strong {{

    color: #5fffe1;
}}


/* ======================================================
   RESPONSIVE
====================================================== */

@media (
    max-width: 1000px
) {{

    .stats {{

        grid-template-columns:
            repeat(
                2,
                1fr
            );
    }}

}}


@media (
    max-width: 700px
) {{

    h1 {{

        font-size: 30px;
    }}


    .stats {{

        grid-template-columns:
            1fr;
    }}


    .diff-header,
    .diff-row {{

        grid-template-columns:
            1fr;
    }}

}}

</style>

</head>


<body>


<div class="container">


    <!-- ===============================================
         CODESENTINEL AI BRAND
    ================================================ -->

    <div class="brand-banner">

        <img
            src="../assets/codesentinel-banner.png"
            alt="CodeSentinel AI Banner"
        >

    </div>


    <h1>
        🛡️ CodeSentinel AI
    </h1>


    <div class="subtitle">

        AI-Powered Code Review
        & Security Analysis Assistant

        <br>

        Detect • Analyze • Improve • Secure

    </div>


    <!-- ===============================================
         REVIEW STATS
    ================================================ -->

    <div class="stats">


        <div class="stat-card">

            <span>
                Files Reviewed
            </span>

            <b>
                {len(files)}
            </b>

        </div>


        <div class="stat-card">

            <span>
                Total Findings
            </span>

            <b>
                {len(findings)}
            </b>

        </div>


        <div class="stat-card">

            <span>
                Critical
            </span>

            <b>
                {critical_count}
            </b>

        </div>


        <div class="stat-card">

            <span>
                High
            </span>

            <b>
                {high_count}
            </b>

        </div>


        <div class="stat-card">

            <span>
                Medium
            </span>

            <b>
                {medium_count}
            </b>

        </div>


        <div class="stat-card">

            <span>
                Review Time
            </span>

            <b>
                {elapsed:.4f}s
            </b>

        </div>


    </div>


    <!-- ===============================================
         FINDINGS
    ================================================ -->

    <div class="section-title">

        🔍 Review Findings

    </div>


    <div class="table-wrapper">


        <table>


            <thead>

                <tr>

                    <th>
                        Severity
                    </th>

                    <th>
                        File
                    </th>

                    <th>
                        Line
                    </th>

                    <th>
                        Category
                    </th>

                    <th>
                        Issue
                    </th>

                    <th>
                        Recommendation
                    </th>

                </tr>

            </thead>


            <tbody>

                {
                    "".join(
                        finding_rows
                    )
                }

            </tbody>


        </table>


    </div>


    <!-- ===============================================
         ORIGINAL VS RECOMMENDED
    ================================================ -->

    <div class="section-title">

        🆚 Original vs Recommended

    </div>


    {

        "".join(
            diff_sections
        )

        if diff_sections

        else

        """
        <div class="stat-card">

            No safe automatic text transformation
            was available for this review.

        </div>
        """

    }


    <!-- ===============================================
         FOOTER
    ================================================ -->

    <div class="footer">

        Generated by

        <strong>
            CodeSentinel AI
        </strong>

        <br>

        Better Code. Safer Tomorrow.

    </div>


</div>


</body>

</html>
"""


    report_file = (
        report_directory
        /
        "review_report.html"
    )


    report_file.write_text(
        document,
        encoding="utf-8"
    )


# ============================================================
# MARKDOWN REPORT
# ============================================================

def create_markdown_report(
    findings: list[Finding],
    files_count: int,
    elapsed: float,
    report_directory: Path
) -> None:

    lines = [

        "# CodeSentinel AI Review Report",

        "",

        (
            f"- Files Reviewed: "
            f"**{files_count}**"
        ),

        (
            f"- Findings: "
            f"**{len(findings)}**"
        ),

        (
            f"- Review Time: "
            f"**{elapsed:.4f}s**"
        ),

        "",
    ]


    for index, finding in enumerate(
        findings,
        start=1
    ):

        lines.extend(

            [

                (
                    f"## {index}. "
                    f"[{finding.severity}] "
                    f"{finding.title}"
                ),

                "",

                (
                    f"- **File:** "
                    f"`{finding.file}`"
                ),

                (
                    f"- **Line:** "
                    f"`{finding.line}`"
                ),

                (
                    f"- **Category:** "
                    f"`{finding.category}`"
                ),

                (
                    f"- **Rule:** "
                    f"`{finding.rule}`"
                ),

                "",

                (
                    f"**Why:** "
                    f"{finding.explanation}"
                ),

                "",

                (
                    f"**Suggestion:** "
                    f"{finding.suggestion}"
                ),

                "",

            ]

        )


    (
        report_directory
        /
        "review_report.md"
    ).write_text(

        "\n".join(lines),

        encoding="utf-8"
    )


# ============================================================
# JSON REPORT
# ============================================================

def create_json_report(
    findings: list[Finding],
    files_count: int,
    elapsed: float,
    report_directory: Path
) -> None:

    data = {

        "tool":
            "CodeSentinel AI",

        "files_reviewed":
            files_count,

        "finding_count":
            len(findings),

        "review_time_seconds":
            elapsed,

        "findings":
            [
                asdict(finding)
                for finding
                in findings
            ]
    }


    (
        report_directory
        /
        "review_report.json"
    ).write_text(

        json.dumps(
            data,
            indent=4
        ),

        encoding="utf-8"
    )


# ============================================================
# REVIEW ENGINE
# ============================================================

def run_review(
    files: list[Path],
    base: Path,
    report_directory: Path
):

    start_time = (
        time.perf_counter()
    )

    findings = []


    for source_file in files:

        findings.extend(
            scan_file(
                source_file
            )
        )


    elapsed = (
        time.perf_counter()
        -
        start_time
    )


    findings = (
        normalize_findings(
            findings,
            base
        )
    )


    findings = (
        deduplicate_findings(
            findings
        )
    )


    print_terminal_report(
        findings,
        len(files),
        elapsed
    )


    report_directory.mkdir(
        parents=True,
        exist_ok=True
    )


    create_html_report(
        findings,
        files,
        base,
        elapsed,
        report_directory
    )


    create_markdown_report(
        findings,
        len(files),
        elapsed,
        report_directory
    )


    create_json_report(
        findings,
        len(files),
        elapsed,
        report_directory
    )


    print()

    print(
        "Reports created:"
    )

    print(
        f"  "
        f"{report_directory / 'review_report.html'}"
    )

    print(
        f"  "
        f"{report_directory / 'review_report.md'}"
    )

    print(
        f"  "
        f"{report_directory / 'review_report.json'}"
    )


# ============================================================
# CLI
# ============================================================

def main():

    parser = argparse.ArgumentParser(

        description=(
            "CodeSentinel AI - "
            "Intelligent Code Review "
            "& Security Analysis Assistant"
        )
    )


    subparsers = (
        parser
        .add_subparsers(
            dest="command",
            required=True
        )
    )


    # ========================================================
    # SCAN COMMAND
    # ========================================================

    scan_parser = (
        subparsers
        .add_parser(
            "scan",
            help=(
                "Review a file "
                "or complete project."
            )
        )
    )


    scan_parser.add_argument(
        "target",
        help=(
            "Source file or project "
            "folder to review."
        )
    )


    scan_parser.add_argument(
        "--report-dir",
        default="reports",
        help=(
            "Directory where reports "
            "will be created."
        )
    )


    # ========================================================
    # GIT REVIEW COMMAND
    # ========================================================

    review_parser = (
        subparsers
        .add_parser(
            "review",
            help=(
                "Review source files "
                "changed between Git refs."
            )
        )
    )


    review_parser.add_argument(
        "--base",
        default="HEAD~1",
        help=(
            "Base Git revision."
        )
    )


    review_parser.add_argument(
        "--target",
        default="HEAD",
        help=(
            "Target Git revision."
        )
    )


    review_parser.add_argument(
        "--report-dir",
        default="reports",
        help=(
            "Directory where reports "
            "will be created."
        )
    )


    args = parser.parse_args()


    # ========================================================
    # FULL PROJECT SCAN
    # ========================================================

    if args.command == "scan":

        target = Path(
            args.target
        )


        files = collect_source_files(
            target
        )


        if target.is_dir():

            base = target

        else:

            base = target.parent


    # ========================================================
    # GIT DIFF REVIEW
    # ========================================================

    else:

        files = changed_git_files(

            args.base,

            args.target
        )


        base = Path.cwd()


    # ========================================================
    # NO FILES
    # ========================================================

    if not files:

        print(
            "[INFO] No supported "
            "source files found."
        )

        return


    # ========================================================
    # RUN REVIEW
    # ========================================================

    run_review(

        files,

        base,

        Path(
            args.report_dir
        )
    )


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":

    main()