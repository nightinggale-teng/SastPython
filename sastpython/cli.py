from __future__ import annotations
import sys
import argparse
import ast
import logging
import shutil
import pyfiglet
from pathlib import Path
from sastpython.core import SecurityAnalyzer
from sastpython.reporter import ConsoleReporter
from sastpython.rules6 import analyze_requirements_text

MAX_BYTES_DEFAULT = 1 * 1024 * 1024  # 1 MB default limit

def is_under_system_path(p: Path) -> bool:
    """Warn users if they try to analyze files under system paths."""
    sys_roots = (Path("/etc"), Path("/usr"), Path("/lib"), Path("/var"), Path("/bin"))
    try:
        return any(root in p.resolve().parents for root in sys_roots)
    except Exception:
        return False

def read_source_file(path: Path, max_bytes: int) -> str | None:
    """Safely read the target file with sanity checks."""
    if not path.exists():
        logging.error("File not found: %s", path)
        return None
    if not path.is_file():
        logging.error("Target is not a file: %s", path)
        return None
    if path.stat().st_size > max_bytes:
        logging.error("File too large (%d bytes > %d limit)", path.stat().st_size, max_bytes)
        return None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        logging.exception("Failed to read file %s: %s", path, e)
        return None

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the AST SecurityAnalyzer on a Python file or scan dependency files.")
    parser.add_argument("target", help="Path to the file to analyze (Python file, requirements.txt, setup.py, etc.).")
    parser.add_argument("-m", "--max-bytes", type=int, default=MAX_BYTES_DEFAULT,
                        help=f"Maximum file size to read (default: {MAX_BYTES_DEFAULT} bytes).")
    parser.add_argument("-a", "--allow-system-paths", action="store_true",
                        help="Allow analyzing files under system directories.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose (debug) logging.")
    parser.add_argument("-d", "--detail", action="store_true",
                        help="After printing the summary, also print detailed findings (default: summary only).")
    parser.add_argument("-p", "--pdf", metavar="OUTPUT_PDF", default=None,
                        help="If specified, write the report to this PDF file in addition to console output.")
    return parser.parse_args(argv)

def center_text(text):
    terminal_width = shutil.get_terminal_size().columns
    lines = text.split("\n")
    centered = "\n".join(line.center(terminal_width) for line in lines)
    return centered

CYAN = "\033[96m"
RESET = "\033[0m"

def banner():
    title = pyfiglet.figlet_format("Static Code Analyzer", font="block")
    author = pyfiglet.figlet_format("Developed by LCT", font="digital")
    message = pyfiglet.figlet_format("Welcome to the Static Application Security Testing for Python!", font="wideterm")
    print(CYAN + center_text(title) + RESET)
    print(CYAN + center_text(author) + RESET)
    print(CYAN + message + RESET)

def main(argv: list[str] | None = None) -> int:
    banner()

    args = parse_args(argv or sys.argv[1:])
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s"
    )

    target_path = Path(args.target)

    if target_path.suffix != ".py":
        logging.warning("Target file does not have a .py extension (continuing anyway).")

    if is_under_system_path(target_path) and not args.allow_system_paths:
        logging.warning("Target file is under a system path. Use --allow-system-paths to override.")

    source = read_source_file(target_path, max_bytes=args.max_bytes)
    if source is None:
        logging.error("Failed to read source file.")
        return 2

    issues = []

    # If target is a Python file -> AST path
    if target_path.suffix == ".py":
        try:
            tree = ast.parse(source, filename=str(target_path))
        except SyntaxError as se:
            logging.error("Syntax error while parsing %s: %s", target_path, se)
            return 3
        except Exception as e:
            logging.exception("Unexpected error during AST parse: %s", e)
            return 4

        try:
            analyzer = SecurityAnalyzer(source)  # type: ignore[name-defined]
            analyzer.visit(tree)
            issues = getattr(analyzer, "issues", [])
        except Exception as e:
            logging.exception("Analyzer failed: %s", e)
            return 5
    else:
        # Non-Python dependency files
        name_lower = target_path.name.lower()
        requirements_like = {
            "requirements.txt", "requirements.in", "requirement.txt", "requirement.in",
            "requirements-dev.txt", "requirements.dev.txt", "requirements-dev.in",
            "requirement-dev.txt", "requirement.dev.txt", "requirement-dev.in",
            "dev-requirements.txt", "test-requirements.txt", "prod-requirements.txt",
            "dev-requirement.txt", "test-requirement.txt", "prod-requirement.txt",
            "requirements-base.txt", "base.txt", "requirement-base.txt",
        }
        constraints_like = {"constraints.txt", "constraints.in", "constraint.txt", "constraint.in"}
        pipenv_like = {"pipfile", "pipfile.lock"}
        poetry_like = {"poetry.lock"}
        conda_like = {"environment.yml", "environment.yaml", "conda.yml", "conda.yaml"}
        build_cfg_like = {"setup.cfg", "flit.ini", "hatch.toml", "pyproject.toml"}

        if name_lower in requirements_like:
            issues = analyze_requirements_text(source)
        elif name_lower in constraints_like:
            issues = analyze_requirements_text(source)
        elif name_lower in pipenv_like:
            issues = analyze_requirements_text(source)
        elif name_lower in poetry_like:
            issues = analyze_requirements_text(source)
        elif name_lower in conda_like:
            issues = analyze_requirements_text(source)
        elif name_lower in build_cfg_like:
            issues = analyze_requirements_text("\n".join([l for l in source.splitlines() if "[" not in l]))
        else:
            logging.warning("Unknown non-Python file type; running generic dependency scan.")
            issues = analyze_requirements_text(source)

    logging.info("Analysis complete. %d issue(s) found.", len(issues))

    def _normalize_issues_for_report(issues_raw) -> list[dict]:
        """
        Defensive normalization of issues returned by analyzers:
        - flatten nested lists,
        - keep only dicts,
        - ensure required keys exist.
        """
        flattened = []

        def _recurse(x):
            if x is None:
                return
            if isinstance(x, dict):
                issue = {
                    "line": x.get("line", "?"),
                    "function": x.get("function", ""),
                    "category": x.get("category", ""),
                    "rule": x.get("rule", ""),
                    "vulnerability": x.get("vulnerability", ""),
                    "severity": x.get("severity", "INFO"),
                    "description": x.get("description", ""),
                    "recommendation": x.get("recommendation", "")
                }
                # preserve extras
                for k, v in x.items():
                    if k not in issue:
                        issue[k] = v
                flattened.append(issue)
                return
            if isinstance(x, (list, tuple)):
                for elem in x:
                    _recurse(elem)
                return
            # otherwise ignore non-dict items (but log for debugging)
            logging.debug("Ignoring unexpected issue item of type %s: %r", type(x), x)

        _recurse(issues_raw)
        return flattened

    # after computing `issues` (line where `issues = getattr(analyzer, "issues", [])` or dependency analysis)
    issues = _normalize_issues_for_report(issues)

    # Print console report
    try:
        reporter = ConsoleReporter(source, issues)  # type: ignore[name-defined]
        reporter.print_summary()
        if args.detail:
            try:
                reporter.print_detail()
            except Exception as e:
                logging.exception("ConsoleReporter.print_detail failed: %s", e)
                # fallback: print each issue in simple text form
                for issue in issues:
                    print(f"[{issue.get('severity','INFO')}] line {issue.get('line','?')}: {issue.get('vulnerability')}")
    except Exception as e:
        logging.exception("ConsoleReporter failed: %s", e)
        for issue in issues:
            print(f"[{issue.get('severity', 'INFO')}] line {issue.get('line', '?')}: {issue.get('vulnerability')}")

    if args.pdf:
        try:
            out_pdf = Path(args.pdf)
            if not out_pdf.parent.exists():
                out_pdf.parent.mkdir(parents=True, exist_ok=True)
            reporter.export_pdf(str(out_pdf))
            logging.info("PDF report written to %s", out_pdf)
        except Exception as e:
            logging.exception("Failed to export PDF report: %s", e)

    return 0

def _entry_point():
    raise SystemExit(main())

if __name__ == "__main__":
    _entry_point()
