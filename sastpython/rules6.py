from __future__ import annotations
import ast
import logging
import re
from typing import Optional, Sequence

# === A06 Vulnerable and Outdated Components ===

# --- Known vulnerable library versions and heuristics ---
KNOWN_VULN_LIBS = {
    "django": [
        "<2.2.18",        # CVE-2021-3281 affected 2.2 before 2.2.18
        "<3.0.12",        # CVE-2021-3281 affected 3.0 before 3.0.12
        "<3.1.6",         # CVE-2021-3281 affected 3.1 before 3.1.6
        "regex:\\b1\\.11\\b",   # legacy EOL Django 1.11 series frequently vulnerable
    ],
    "requests": [
        "<2.20.0",        # CVE-2018-18074: requests before 2.20.0 exposed auth on redirects
        "2.19.0",         # older fixed versions to flag explicitly
    ],
    "urllib3": [
        "<1.24.2",        # CVE-2019-11324
        "1.24.1",
    ],
    "pyyaml": [
        "<5.1",           # yaml.load arbitrary code execution before 5.1
        "5.1",
    ],
    "jinja2": [
        "<2.10.1",        # sandbox escape via format_map fixed in 2.10.1
        "2.10.1",
    ],
    "flask": [
        "<1.0",           # CVE(s) that affect Flask < 1.0 (DoS / other fixed in 1.0+)
        "1.1.1",          # older version commonly flagged in scanners
    ],
    "paramiko": [
        "<2.11.0",        # example: older paramiko releases had multiple crypto/transport fixes
        "2.8",            # specific older version to flag
    ],
    "xmltodict": [
        "0.11",           # known historical XXE/parse issues reported for older xmltodict
        "<1.0.0",
    ],
    "sqlalchemy": [
        "regex:\\b1\\.3\\.|regex:\\b1\\.2\\.",  # old SQLAlchemy series often have fixes
    ],
    "numpy": [
        "regex:\\b1\\.[0-9]+\\.|regex:\\b2\\.0\\.0b", # pre-release / old series detection
    ],
}

DANGEROUS_VERSION_PATTERNS = [
    r"<\s*\d",                    # e.g. "jinja2<3"  (open upper-bound)
    r"<=?\s*\d+(\.\d+)*",         # explicit <= or < version ranges
    r"==\s*latest\b",             # pkg==latest
    r"\b(latest)\b",              # 'latest' anywhere
    r"\*\b",                      # wildcard anywhere (==*)
    r"==\s*\*$",                  # exact "==*"
    r"(?:a|b|rc|dev|alpha|beta|pre)\d*$",  # pre-release/dev tags like b1, rc1, dev0
    r"\b(unpinned|none)\b",       # textual hints
    r"git\+[^@]+$",               # git+... without @ means unpinned
    r"git\+.*@(main|master|develop|dev|HEAD)\b",  # pinned to branch -> still risky
    r"regex:",                    # marker for regex entries in KNOWN_VULN_LIBS
    r"\b(post|build)\d*\b",       # version metadata tokens (post/build) - sometimes risky
    r"~=|>=|<=",                  # any non-exact comparators (if your policy forbids ranges)
]

GIT_UNPINNED_PATTERN = re.compile(r"git\+[^@]+$")       # no @tag or @commit

# Helper for code snippet
def safe_unparse(node):
    try:
        return ast.unparse(node)
    except Exception:
        try:
            # Best-effort fallback for constants
            if isinstance(node, ast.Constant):
                return repr(node.value)
            return str(node)
        except Exception:
            return ""
        
def _try_eval_constant(node: ast.AST) -> Optional[str]:
    """Return a string value from simple AST nodes, else None."""
    try:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Str):  # py<3.8 fallback
            return node.s
        if isinstance(node, ast.JoinedStr):  # f-string with constant parts
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                else:
                    return None
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            l = _try_eval_constant(node.left)
            r = _try_eval_constant(node.right)
            if l is not None and r is not None:
                return l + r
    except Exception:
        pass
    return None

def parse_pkg_string(pkg_string: str) -> tuple[str, Optional[str]]:
    raw = (pkg_string or "").strip()
    if raw.startswith("git+"):
        m = re.search(r"git\+[^/]+/(?:.*/)?([^/@#\s]+)(?:\.git)?(?:@([^#\s]+))?", raw)
        name = m.group(1).lower() if m else "unknown"
        return name, raw
    # drop environment markers
    body = raw.split(";", 1)[0].strip()
    # strip extras like pkg[extra]
    m = re.match(r"^([A-Za-z0-9_\-\.]+)", body)
    name = (m.group(1).lower() if m else body.lower())
    rest = body[len(m.group(0)) :].strip() if m else ""
    return name, rest or None

def _check_version_patterns(name: str, version: Optional[str]) -> bool:
    if not version:
        return False
    v = version.strip()
    if name in KNOWN_VULN_LIBS:
        for vuln in KNOWN_VULN_LIBS[name]:
            if re.search(r"\b" + re.escape(vuln) + r"\b", v):
                return True
    for pat in DANGEROUS_VERSION_PATTERNS:
        if re.search(pat, v, flags=re.I):
            return True
    if v.startswith("git+") and GIT_UNPINNED_PATTERN.search(v):
        return True
    if "latest" in v.lower() or "*" in v:
        return True
    return False

# -------------------------
# Name-resolution helper: find the last assignment to a name before a given lineno
# -------------------------
def _find_last_assignment_for_name(tree: ast.Module, name: str, lineno_before: int) -> Optional[ast.AST]:
    """
    Search the module AST for Assign/AnnAssign where a target is 'name' and
    return the value node from the assignment having the highest lineno < lineno_before.
    """
    best_node = None
    best_lineno = -1
    for node in ast.walk(tree):
        # consider Assign (a = ...), AnnAssign (a: list = ...), maybe simple Name targets only
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    node_lineno = getattr(node, "lineno", 0)
                    if 0 < node_lineno < lineno_before and node_lineno > best_lineno:
                        best_node = node.value
                        best_lineno = node_lineno
        elif isinstance(node, ast.AnnAssign):
            tgt = node.target
            if isinstance(tgt, ast.Name) and tgt.id == name:
                node_lineno = getattr(node, "lineno", 0)
                if 0 < node_lineno < lineno_before and node_lineno > best_lineno:
                    best_node = node.value
                    best_lineno = node_lineno
    return best_node

def _extract_list_of_strings_with_linenos(node: ast.AST) -> Optional[ast.List[tuple[str, int]]]:
    """
    Given an AST node expected to be a List/Tuple, return list of (string, lineno)
    for each element that can be recovered as a string. If it's a single string
    node, return [(string, lineno)].
    Returns None if not recoverable at all (complex elements).
    """
    if node is None:
        return None

    if isinstance(node, (ast.List, ast.Tuple)):
        out: ast.List[tuple[str, int]] = []
        for elt in node.elts:
            s = _try_eval_constant(elt)
            lineno = getattr(elt, "lineno", getattr(node, "lineno", 0))
            if s is None:
                # If element is not a recoverable constant, include a best-effort source segment
                try:
                    seg = ast.get_source_segment(getattr(analyzer_global, "source_code", ""), elt) or "<complex_expr>"
                except Exception:
                    seg = "<complex_expr>"
                # still append the textual representation so we can attempt pattern matching later
                out.append((seg, lineno))
            else:
                out.append((s, lineno))
        return out

    # if node is a single string constant
    s = _try_eval_constant(node)
    if s is not None:
        lineno = getattr(node, "lineno", 0)
        return [(s, lineno)]

    return None

# ---------- helpers for standardized findings ----------
def _extract_snippet_for_node(node, analyzer, context=1):
    """
    Returns a 3-line code snippet (line numbers included) around node.lineno using analyzer.source_code
    Falls back to ast.unparse or safe_unparse for best-effort snippet when source not available.
    """
    lineno = getattr(node, "lineno", None)
    src = getattr(analyzer, "source_code", None) if analyzer is not None else None
    if src and lineno:
        try:
            lines = src.splitlines()
            idx = max(0, lineno - 1)
            start = max(0, idx - context)
            end = min(len(lines), idx + context + 1)
            snippet_lines = []
            for i in range(start, end):
                prefix = f"{i+1:>4}: "
                snippet_lines.append(prefix + lines[i])
            return "\n".join(snippet_lines)
        except Exception:
            pass
    # fallback: try to unparse node or produce short repr
    try:
        return safe_unparse(node)
    except Exception:
        return "<source unavailable>"

def _make_vuln_finding(analyzer, node_like, vuln_id, vuln_name, severity, description, recommendation, extra=None):
    """
    Standardized finding object used by A06 checks.
    node_like: AST node or a tuple (text, lineno) where code_snippet is built from text.
    """
    # resolve line and snippet
    if isinstance(node_like, tuple) and len(node_like) == 2 and isinstance(node_like[0], str):
        text, lineno = node_like
        # create a small snippet using the text itself
        snippet = f"{text}"
    else:
        node = node_like
        lineno = getattr(node, "lineno", 0)
        snippet = _extract_snippet_for_node(node, analyzer)

    finding = {
        "line": lineno or 0,
        "function": snippet,
        "category": "A06 Vulnerable/Outdated Components",
        "rule": vuln_id,
        "vulnerability": vuln_name,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    }
    if extra and isinstance(extra, dict):
        finding.update(extra)
    return finding

# -------------------------------
# AST-based scanning
# -------------------------------
def check_vulnerable_dependencies(node: ast.AST, analyzer=None) -> Optional[ast.List[dict]]:
    """
    Returns a list of standardized findings (or None).
    Reuses parse_pkg_string and _check_version_patterns; maps matches to A06 IDs.
    """
    global analyzer_global
    analyzer_global = analyzer

    findings: list = []
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."

    def _scan_pkg_items(pkg_items: Sequence[tuple[str, int]]):
        for pkg_line, lineno in pkg_items:
            name, version = parse_pkg_string(pkg_line)
            matched = _check_version_patterns(name, version)
            if not matched:
                continue

            # Decide which vulnerability ID / message to use based on heuristics
            # 01 Known vulnerable package version (explicit match in KNOWN_VULN_LIBS)
            if name in KNOWN_VULN_LIBS and any(re.search(r"\b" + re.escape(v) + r"\b", (version or ""), flags=re.I) for v in KNOWN_VULN_LIBS[name]):
                findings.append(_make_vuln_finding(
                    analyzer,
                    (pkg_line, lineno),
                    vuln_id="601",
                    vuln_name="Known vulnerable package version",
                    severity="HIGH",
                    description="A package/version matches an entry in your KNOWN_VULN_LIBS (for example django<2.2.18, pyyaml<5.1, etc.). These are explicit signals that the dependency is on a version historically associated with CVEs or security bugs.",
                    recommendation="Upgrade to a non-vulnerable release (consult vendor advisories/CVE database). If upgrade not possible, backport fixes, apply compensating controls, or isolate the vulnerable component. Add a dependency policy and automated CVE checks in CI.",
                    extra={"pkg_name": name, "version_spec": version or pkg_line, "matched_pattern": "KNOWN_VULN_LIBS"}
                ))
                continue

            # 02 Open/unsafe version range (e.g., < without >=, or range tokens)
            if any(re.search(pat, (version or ""), flags=re.I) for pat in DANGEROUS_VERSION_PATTERNS):
                # Distinguish particular cases:
                vtxt = version or pkg_line
                if re.search(r"git\+[^@]+$", vtxt):
                    findings.append(_make_vuln_finding(
                        analyzer,
                        (pkg_line, lineno),
                        vuln_id="603",
                        vuln_name="Unpinned git dependency",
                        severity="MEDIUM",
                        description="Git URL dependency without a pinned commit or tag are non-reproducible and can silently change when the remote branch is updated — a supply-chain risk.",
                        recommendation="Pin git dependencies to a tag or commit SHA (e.g., @v1.2.3 or @<sha>). Prefer released packages on package indexes and use lockfiles (pip-tools/Poetry/Pipenv) to ensure reproducible installs.",
                        extra={"pkg_name": name, "version_spec": version or pkg_line, "matched_pattern": "GIT_UNPINNED"}
                    ))
                    continue

                if re.search(r"\b(latest)\b", vtxt, flags=re.I) or "*" in vtxt:
                    findings.append(_make_vuln_finding(
                        analyzer,
                        (pkg_line, lineno),
                        vuln_id="604",
                        vuln_name="Use of 'latest' or wildcard pins",
                        severity="MEDIUM",
                        description="Using latest, *, or wildcard pins (including ==latest or ==*) allows installing arbitrary versions, making builds non-reproducible and vulnerable to malicious or accidental changes.",
                        recommendation="Avoid 'latest' or wildcards; specify explicit secure ranges and use automated upgrade/testing pipelines to periodically refresh and test upgrades rather than floating pins.",
                        extra={"pkg_name": name, "version_spec": vtxt, "matched_pattern": "LATEST_OR_WILDCARD"}
                    ))
                    continue

                # generic open-range / comparator match
                findings.append(_make_vuln_finding(
                    analyzer,
                    (pkg_line, lineno),
                    vuln_id="602",
                    vuln_name="Open/unsafe version range",
                    severity="MEDIUM",
                    description="Use of non-exact comparators or open upper bounds can allow installation of older, vulnerable releases or unexpected versions. Ranges such as <1.2 without a matching lower-bound are risky.",
                    recommendation="Prefer pinned minimums with an upper bound policy (e.g., >=1.2,<2.0) or use curated constraints files. Enforce dependency policy in CI that disallows open upper-bounds or requires justification.",
                    extra={"pkg_name": name, "version_spec": version or pkg_line, "matched_pattern": "DANGEROUS_VERSION_PATTERN"}
                ))
                continue

            # fallback: regex-based matches in KNOWN_VULN_LIBS (A06-12)
            # (e.g., 'regex:' entries)
            if name in KNOWN_VULN_LIBS:
                vuln_matches = [v for v in KNOWN_VULN_LIBS[name] if v.startswith("regex:")]
                if vuln_matches:
                    findings.append(_make_vuln_finding(
                        analyzer,
                        (pkg_line, lineno),
                        vuln_id="612",
                        vuln_name="Version pattern match (regex heuristic)",
                        severity="MEDIUM",
                        description="Matching via regex tokens (e.g., entries that start with regex:) is useful to catch broad families but can generate false positives when strings are complex.",
                        recommendation="When reporting regex matches, include the exact matched sub-pattern and example CVE or advisory to reduce noise. Provide confidence scores in findings so triage can prioritize.",
                        extra={"pkg_name": name, "version_spec": version or pkg_line, "matched_pattern": ",".join(vuln_matches)}
                    ))
                    continue

            # If none of the above specifics matched but _check_version_patterns returned true, mark as general suspicious
            findings.append(_make_vuln_finding(
                analyzer,
                (pkg_line, lineno),
                vuln_id="605",
                vuln_name="Suspicious or potentially outdated pinned version",
                severity="MEDIUM",
                description="Exact pins are reproducible but may lock the project to a known-vulnerable release if the pinned version is old and affected by CVEs. Your heuristics flag exact pins of certain packages as suspicious.",
                recommendation="Verify pinned versions against advisories; update pins to secure minima. Use lockfile + scheduled dependency scanning to detect when a pinned version becomes vulnerable.",
                extra={"pkg_name": name, "version_spec": version or pkg_line}
            ))

    # 1) setup(..., install_requires=...)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setup":
        setup_lineno = getattr(node, "lineno", 0)
        for kw in node.keywords:
            if kw.arg != "install_requires":
                continue

            if isinstance(kw.value, (ast.List, ast.Tuple)):
                pkg_items = _extract_list_of_strings_with_linenos(kw.value)
                if pkg_items:
                    _scan_pkg_items(pkg_items)
                else:
                    seg = None
                    try:
                        seg = ast.get_source_segment(getattr(analyzer, "source_code", ""), kw.value) or "<complex_expr>"
                    except Exception:
                        seg = "<complex_expr>"
                    # report as complex/indirect expression (A06-10)
                    if seg and _check_version_patterns(*parse_pkg_string(seg)):
                        findings.append(_make_vuln_finding(
                            analyzer,
                            (seg, getattr(kw.value, "lineno", setup_lineno)),
                            vuln_id="610",
                            vuln_name="Complex/indirect dependency expression",
                            severity="INFO",
                            description="Entries created by complex expressions (concatenation, function calls, computed variables) cannot be fully analyzed statically and may hide unsafe specs or dynamic content.",
                            recommendation="Encourage simple literal lists in install_requires or use a requirements.txt for scanning. If variables are used, ensure they are defined as simple literals near their use or add a pre-processing step in CI to render/runtime-evaluate dependency files safely.",
                            extra={"matched_pattern": seg}
                        ))
                continue

            elif isinstance(kw.value, ast.Name):
                name_ref = kw.value.id
                tree = getattr(analyzer, "source_tree", None) or (ast.parse(getattr(analyzer, "source_code", "")) if analyzer and getattr(analyzer, "source_code", None) else None)
                if isinstance(tree, ast.Module):
                    assigned_val = _find_last_assignment_for_name(tree, name_ref, setup_lineno)
                    if assigned_val is not None:
                        pkg_items = _extract_list_of_strings_with_linenos(assigned_val)
                        if pkg_items:
                            _scan_pkg_items(pkg_items)
                        else:
                            # can't enumerate; report unresolved variable (A06-11)
                            seg = None
                            try:
                                seg = ast.get_source_segment(getattr(analyzer, "source_code", ""), assigned_val) or f"<{name_ref}>"
                            except Exception:
                                seg = f"<{name_ref}>"
                            if _check_version_patterns(*parse_pkg_string(seg)):
                                findings.append(_make_vuln_finding(
                                    analyzer,
                                    (seg, getattr(assigned_val, "lineno", getattr(kw.value, "lineno", setup_lineno))),
                                    vuln_id="611",
                                    vuln_name="Install_requires referenced via variable (unresolved before setup)",
                                    severity="MEDIUM",
                                    description="When install_requires is a variable that cannot be resolved statically (no earlier assignment), the analyzer must fall back to textual heuristics — the package spec may be hidden or injected at runtime.",
                                    recommendation="Move install_requires to literals or load a static file so scanners can inspect it deterministically. Document runtime modifications and ensure CI runs the same code that builds releases to capture injected dependencies.",
                                    extra={"pkg_name": name_ref, "matched_pattern": seg}
                                ))
                    else:
                        # no earlier assignment: unresolved variable usage (A06-11)
                        seg = None
                        try:
                            seg = ast.get_source_segment(getattr(analyzer, "source_code", ""), kw.value) or f"<{name_ref}>"
                        except Exception:
                            seg = f"<{name_ref}>"
                        if _check_version_patterns(*parse_pkg_string(seg)):
                            findings.append(_make_vuln_finding(
                                analyzer,
                                (seg, getattr(kw.value, "lineno", setup_lineno)),
                                vuln_id="611",
                                    vuln_name="Install_requires referenced via variable (unresolved before setup)",
                                    severity="MEDIUM",
                                    description="When install_requires is a variable that cannot be resolved statically (no earlier assignment), the analyzer must fall back to textual heuristics — the package spec may be hidden or injected at runtime.",
                                    recommendation="Move install_requires to literals or load a static file so scanners can inspect it deterministically. Document runtime modifications and ensure CI runs the same code that builds releases to capture injected dependencies.",
                                extra={"pkg_name": name_ref, "matched_pattern": seg}
                            ))
                else:
                    # no tree available: fallback textual heuristic (A06-10)
                    seg = None
                    try:
                        seg = ast.get_source_segment(getattr(analyzer, "source_code", ""), kw.value) or f"<{name_ref}>"
                    except Exception:
                        seg = f"<{name_ref}>"
                    if _check_version_patterns(*parse_pkg_string(seg)):
                        findings.append(_make_vuln_finding(
                            analyzer,
                            (seg, getattr(kw.value, "lineno", setup_lineno)),
                            vuln_id="610",
                            vuln_name="Complex/indirect dependency expression",
                            severity="INFO",
                            description="Entries created by complex expressions (concatenation, function calls, computed variables) cannot be fully analyzed statically and may hide unsafe specs or dynamic content.",
                            recommendation="Encourage simple literal lists in install_requires or use a requirements.txt for scanning. If variables are used, ensure they are defined as simple literals near their use or add a pre-processing step in CI to render/runtime-evaluate dependency files safely.",
                            extra={"matched_pattern": seg}
                        ))
                continue

            else:
                # other complex expressions inside setup install_requires
                seg = None
                try:
                    seg = ast.get_source_segment(getattr(analyzer, "source_code", ""), kw.value) or "<complex_expr>"
                except Exception:
                    seg = "<complex_expr>"
                if _check_version_patterns(*parse_pkg_string(seg)):
                    findings.append(_make_vuln_finding(
                        analyzer,
                        (seg, getattr(kw.value, "lineno", setup_lineno)),
                        vuln_id="610",
                        vuln_name="Complex/indirect dependency expression",
                        severity="INFO",
                        description="Entries created by complex expressions (concatenation, function calls, computed variables) cannot be fully analyzed statically and may hide unsafe specs or dynamic content.",
                        recommendation="Encourage simple literal lists in install_requires or use a requirements.txt for scanning. If variables are used, ensure they are defined as simple literals near their use or add a pre-processing step in CI to render/runtime-evaluate dependency files safely.",
                        extra={"matched_pattern": seg}
                    ))
        return findings or None

    # 2) top-level assignment: install_requires = [...]
    if isinstance(node, ast.Assign):
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id == "install_requires":
                val = node.value
                pkg_items = _extract_list_of_strings_with_linenos(val)
                if pkg_items:
                    _scan_pkg_items(pkg_items)
                else:
                    seg = None
                    try:
                        seg = ast.get_source_segment(getattr(analyzer, "source_code", ""), val) or "<complex_expr>"
                    except Exception:
                        seg = "<complex_expr>"
                    if _check_version_patterns(*parse_pkg_string(seg)):
                        findings.append(_make_vuln_finding(
                            analyzer,
                            (seg, getattr(node, "lineno", 0)),
                            vuln_id="610",
                            vuln_name="Complex/indirect dependency expression",
                            severity="INFO",
                            description="Entries created by complex expressions (concatenation, function calls, computed variables) cannot be fully analyzed statically and may hide unsafe specs or dynamic content.",
                            recommendation="Encourage simple literal lists in install_requires or use a requirements.txt for scanning. If variables are used, ensure they are defined as simple literals near their use or add a pre-processing step in CI to render/runtime-evaluate dependency files safely.",
                            extra={"matched_pattern": seg}
                        ))
                return findings or None

    return findings or None

# ---------- update textual requirements scanner to return standardized findings ----------
def analyze_requirements_text(text: str) -> list[dict]:
    """
    Scan a requirements-style text and return a list of standardized issue dicts.
    """
    issues: list = []
    KNOWN_UNSAFE = {"pickle", "pickle5", "xmltodict", "paramiko"}  # extend as needed
    lines = text.splitlines()
    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        clean = re.split(r"\s+#", line, 1)[0].strip()

        # git-based URL without pinned tag/commit -> A06-03
        if clean.startswith("git+") and "@" not in clean:
            issues.append(_make_vuln_finding(
                analyzer=None,
                node_like=(clean, idx),
                vuln_id="603",
                vuln_name="Unpinned git dependency",
                severity="MEDIUM",
                description="Git URL dependency without a pinned commit or tag are non-reproducible and can silently change when the remote branch is updated — a supply-chain risk.",
                recommendation="Pin git dependencies to a tag or commit SHA (e.g., @v1.2.3 or @<sha>). Prefer released packages on package indexes and use lockfiles (pip-tools/Poetry/Pipenv) to ensure reproducible installs.",
                extra={"raw": clean}
            ))
            continue

        # pinned exact version -> A06-05 (flag for review)
        if "==" in clean:
            pkg, ver = [p.strip() for p in clean.split("==", 1)]
            issues.append(_make_vuln_finding(
                analyzer=None,
                node_like=(clean, idx),
                vuln_id="605",
                vuln_name="Suspicious or potentially outdated pinned version",
                severity="MEDIUM",
                description="Exact pins are reproducible but may lock the project to a known-vulnerable release if the pinned version is old and affected by CVEs. Your heuristics flag exact pins of certain packages as suspicious.",
                recommendation="Verify pinned versions against advisories; update pins to secure minima. Use lockfile + scheduled dependency scanning to detect when a pinned version becomes vulnerable.",
                extra={"pkg_name": pkg.lower(), "version_spec": ver}
            ))
            # heuristics: certain packages get HIGH
            if re.match(r"^\d+\.\d+\.\d+$", ver) and (pkg.lower() in ("django", "flask", "requests", "pyyaml")):
                issues.append(_make_vuln_finding(
                    analyzer=None,
                    node_like=(clean, idx),
                    vuln_id="601",
                    vuln_name="Known vulnerable package version",
                    severity="HIGH",
                    description="A package/version matches an entry in your KNOWN_VULN_LIBS (for example django<2.2.18, pyyaml<5.1, etc.). These are explicit signals that the dependency is on a version historically associated with CVEs or security bugs.",
                    recommendation="Upgrade to a non-vulnerable release (consult vendor advisories/CVE database). If upgrade not possible, backport fixes, apply compensating controls, or isolate the vulnerable component. Add a dependency policy and automated CVE checks in CI.",
                    extra={"pkg_name": pkg.lower(), "version_spec": ver}
                ))
            continue

        # latest token -> A06-04
        if re.search(r"\b(latest)\b", clean, flags=re.I):
            issues.append(_make_vuln_finding(
                analyzer=None,
                node_like=(clean, idx),
                vuln_id="604",
                vuln_name="Use of 'latest' or wildcard pins",
                severity="MEDIUM",
                description="Using latest, *, or wildcard pins (including ==latest or ==*) allows installing arbitrary versions, making builds non-reproducible and vulnerable to malicious or accidental changes.",
                recommendation="Avoid 'latest' or wildcards; specify explicit secure ranges and use automated upgrade/testing pipelines to periodically refresh and test upgrades rather than floating pins.",
                extra={"raw": clean}
            ))
            continue

        # '<' without '>=' -> A06-02
        if "<" in clean and not ">=" in clean:
            issues.append(_make_vuln_finding(
                analyzer=None,
                node_like=(clean, idx),
                vuln_id="602",
                    vuln_name="Open/unsafe version range",
                    severity="MEDIUM",
                    description="Use of non-exact comparators or open upper bounds can allow installation of older, vulnerable releases or unexpected versions. Ranges such as <1.2 without a matching lower-bound are risky.",
                    recommendation="Prefer pinned minimums with an upper bound policy (e.g., >=1.2,<2.0) or use curated constraints files. Enforce dependency policy in CI that disallows open upper-bounds or requires justification.",
                extra={"raw": clean}
            ))

        # pre-release / alpha / beta -> A06-06
        if re.search(r"(?:a|b|rc|dev|alpha|beta|pre)\d*$", clean):
            issues.append(_make_vuln_finding(
                analyzer=None,
                node_like=(clean, idx),
                vuln_id="606",
                vuln_name="Pre-release / beta / dev version",
                severity="LOW",
                description="Pre-release versions can contain unstable or experimental code and may not have full security fixes—using them in production is risky.",
                recommendation="Avoid pre-releases for production; if intentionally used, document the reason and add extra testing and monitoring. Prefer stable releases for production deployments.",
                extra={"raw": clean}
            ))

        # Known unsafe libs -> A06-09
        pkg_name = re.split(r"[<=>!~\[\];\s]", clean)[0].lower()
        if pkg_name in KNOWN_UNSAFE:
            issues.append(_make_vuln_finding(
                analyzer=None,
                node_like=(clean, idx),
                vuln_id="609",
                vuln_name="Known unsafe or sensitive library referenced in requirements (heuristic list)",
                severity="HIGH",
                description="Presence of particular libraries flagged as “sensitive” (e.g., pickle, pickle5, xmltodict, paramiko per your KNOWN_UNSAFE) indicates risky functionality (unsafe deserialization, XML parsing with XXE risk, or complex crypto code).",
                recommendation="Replace with safer alternatives (JSON for serialization), use safe parsing options (e.g., yaml.safe_load or avoid yaml.load), and minimize surface area. Add security review for any usage of these dependencies and require justification in PRs.",
                extra={"pkg_name": pkg_name}
            ))

        # other dangerous textual tokens -> A06-08
        if re.search(r"\b(unpinned|none|latest)\b", clean, flags=re.I) or "*" in clean:
            issues.append(_make_vuln_finding(
                analyzer=None,
                node_like=(clean, idx),
                vuln_id="608",
                vuln_name="Dangerous textual tokens or wildcard metadata",
                severity="MEDIUM",
                description="Textual hints like unpinned, latest, or none in package specs indicate the package line is not pinned or intentionally flexible — supply-chain and reproducibility risk.",
                recommendation="Normalize dependency entries; replace textual placeholders with explicit versions or constraints. Enforce linting of requirements files to reject such tokens.",
                extra={"raw": clean}
            ))

    return issues

# -------------------------------
# run_rules6_on_ast: keep same contract, but accept list returns
# -------------------------------
def run_rules6_on_ast(tree: ast.AST, analyzer=None) -> list:
    """
    Walk AST and run RULES6 rules. Return raw results (list of dicts, possibly nested lists).
    Normalization/flattening is handled by the core analyzer.
    """
    results = []
    for node in ast.walk(tree):
        for rule in RULES6:
            try:
                # rules may accept analyzer parameter
                res = rule(node, analyzer=analyzer)
                if res:
                    results.append(res)
            except Exception:
                logging.exception("rule %s failed at node %s", getattr(rule, "__name__", str(rule)), type(node))
    return results

# Helper to format a single-line "snippet" for requirements lines
def _line_snippet(line: str, lineno: int) -> str:
    return f"{line.rstrip()}"

# -------------------------------
# Text-based scanning
# -------------------------------
def analyze_requirements_text(text: str) -> list[dict]:
    """
    Scan a requirements-style text and return a list of standardized issue dicts.
    Each dict contains:
      line, code_snippet, category, id, vulnerability, severity, description, recommendation
    """
    issues: list[dict] = []
    KNOWN_UNSAFE = {"pickle", "pickle5", "xmltodict", "paramiko"}  # extend as needed
    lines = text.splitlines()

    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if not line.strip() or line.strip().startswith("#"):
            continue

        clean = re.split(r"\s+#", line, 1)[0].strip()
        snippet = _line_snippet(line, idx)
        category = "A06 Vulnerable/Outdated Components"

        # 03 / 07: git-based URL without pinned tag/commit OR pinned to branch names
        if clean.startswith("git+"):
            # unpinned git (no @) -> ID 03
            if "@" not in clean:
                issues.append({
                    "line": idx,
                    "function": snippet,
                    "category": category,
                    "rule": "603",
                    "vulnerability": "Unpinned git dependency",
                    "severity": "MEDIUM",
                    "description": "Git URLs without a pinned commit or tag are non-reproducible and can silently change when the remote branch is updated — a supply-chain risk.",
                    "recommendation": "Pin to a specific tag or commit SHA (@v1.2.3 or @<sha>). Prefer released packages on package indexes and use lockfiles (pip-tools/Poetry/Pipenv) to ensure reproducible installs."
                })
                continue
            # pinned to branch name like @main/@master/@develop -> ID 07
            m = re.search(r"@([^#\s]+)", clean)
            if m:
                ref = m.group(1)
                if ref in ("main", "master", "develop", "dev", "HEAD"):
                    issues.append({
                        "line": idx,
                        "function": snippet,
                        "category": category,
                        "rule": "607",
                        "vulnerability": "Git pinned to branch name",
                        "severity": "MEDIUM",
                        "description": "Pinning a git URL to a branch name still allows that branch to move and does not guarantee immutability — similar to an unpinned git dependency.",
                        "recommendation": "Pin to a commit SHA or immutable tag. If you must use a branch during development, treat it as ephemeral and restrict it to non-production environments."
                    })
                    continue

        # 05 / 09: exact pin to a version and known unsafe libs
        if "==" in clean:
            pkg, ver = [p.strip() for p in clean.split("==", 1)]
            pkg_l = pkg.lower()
            # ID 05: exact pin (may be okay but suspicious if old)
            issues.append({
                "line": idx,
                "function": snippet,
                "category": category,
                "rule": "605",
                "vulnerability": "Exact pinned version",
                "severity": "MEDIUM",
                "description": "Exact pins are reproducible but may lock the project to a known-vulnerable release if the pinned version is old and affected by CVEs. Your heuristics flag exact pins of certain packages as suspicious.",
                "recommendation": "Verify pinned versions against advisories; update pins to secure minima. Use lockfile + scheduled dependency scanning to detect when a pinned version becomes vulnerable."
            })
            # If common framework pinned to a specific semver, flag HIGH per your heuristic
            if re.match(r"^\d+\.\d+\.\d+$", ver) and pkg_l in ("django", "flask", "requests", "pyyaml"):
                issues.append({
                    "line": idx,
                    "function": snippet,
                    "category": category,
                    "rule": "601",
                    "vulnerability": "Known vulnerable package version",
                    "severity": "HIGH",
                    "description": "A package/version matches an entry in your KNOWN_VULN_LIBS (for example django<2.2.18, pyyaml<5.1, etc.). These are explicit signals that the dependency is on a version historically associated with CVEs or security bugs.",
                    "recommendation": "Upgrade to a non-vulnerable release (consult vendor advisories/CVE database). If upgrade not possible, backport fixes, apply compensating controls, or isolate the vulnerable component. Add a dependency policy and automated CVE checks in CI."
                })
            continue

        # 04: "latest" or wildcard usage
        if re.search(r"\b(latest|\*)\b", clean, flags=re.I) or "==" in clean and clean.strip().endswith("==*"):
            issues.append({
                "line": idx,
                "function": snippet,
                "category": category,
                "rule": "604",
                "vulnerability": "Use of latest / wildcard pins",
                "severity": "MEDIUM",
                "description": "Using latest, *, or wildcard pins (including ==latest or ==*) allows installing arbitrary versions, making builds non-reproducible and vulnerable to malicious or accidental changes.",
                "recommendation": "Avoid latest/wildcards. Specify explicit version constraints or use an allowlist of versions. Use automation to periodically refresh and test upgrades rather than floating pins."
            })
            continue

        # 02: '<' without '>=' (open/unsafe version range)
        if "<" in clean and ">=" not in clean:
            issues.append({
                "line": idx,
                "function": snippet,
                "category": category,
                "rule": "602",
                "vulnerability": "Open / unsafe version range",
                "severity": "MEDIUM",
                "description": "Use of non-exact comparators or open upper bounds can allow installation of older, vulnerable releases or unexpected versions. Ranges such as <1.2 without a matching lower-bound are risky.",
                "recommendation": "Prefer pinned minimums with an upper bound policy (e.g., >=1.2,<2.0) or use curated constraints files. Enforce dependency policy in CI that disallows open upper-bounds or requires justification."
            })

        # 06: pre-release / alpha / beta / dev versions (heuristic)
        # check token after '==' or '>=' or standalone version token
        version_token = clean.split("==")[-1] if "==" in clean else clean.split(">=")[-1] if ">=" in clean else clean
        if re.search(r"[a-zA-Z]+[0-9]*$", version_token):
            issues.append({
                "line": idx,
                "function": snippet,
                "category": category,
                "rule": "606",
                "vulnerability": "Pre-release / beta / dev version",
                "severity": "LOW",
                "description": "Pre-release versions can contain unstable or experimental code and may not have full security fixes—using them in production is risky.",
                "recommendation": "Avoid pre-releases for production; if intentionally used, document the reason and add extra testing and monitoring. Prefer stable releases for production deployments."
            })

        # 09: known unsafe or sensitive libraries
        pkg_name = re.split(r"[<=>!~\[\];\s]", clean)[0].lower()
        if pkg_name in KNOWN_UNSAFE:
            issues.append({
                "line": idx,
                "function": snippet,
                "category": category,
                "rule": "609",
                "vulnerability": "Known unsafe or sensitive library referenced",
                "severity": "HIGH",
                "description": "Presence of particular libraries flagged as “sensitive” (e.g., pickle, pickle5, xmltodict, paramiko per your KNOWN_UNSAFE) indicates risky functionality (unsafe deserialization, XML parsing with XXE risk, or complex crypto code).",
                "recommendation": "Replace with safer alternatives (JSON for serialization), use safe parsing options (e.g., yaml.safe_load or avoid yaml.load), and minimize surface area. Add security review for any usage of these dependencies and require justification in PRs."
            })

        # 08: dangerous textual tokens or wildcard metadata
        if re.search(r"\b(unpinned|none|latest|post|build)\b", clean, flags=re.I):
            issues.append({
                "line": idx,
                "function": snippet,
                "category": category,
                "rule": "608",
                "vulnerability": "Dangerous textual tokens or wildcard metadata",
                "severity": "MEDIUM",
                "description": "Textual hints like unpinned, latest, or none in package specs indicate the package line is not pinned or intentionally flexible — supply-chain and reproducibility risk.",
                "recommendation": "Normalize dependency entries; replace textual placeholders with explicit versions or constraints. Enforce linting of requirements files to reject such tokens."
            })

        # 10: complex/indirect expressions (heuristic: brackets, env markers, or non-simple tokens)
        if re.search(r"[\$\{\}\(\)]", clean) or ("; " in clean) or "[" in clean:
            issues.append({
                "line": idx,
                "function": snippet,
                "category": category,
                "rule": "610",
                "vulnerability": "Complex or indirect dependency expression",
                "severity": "INFO",
                "description": "Entries created by complex expressions (concatenation, function calls, computed variables) cannot be fully analyzed statically and may hide unsafe specs or dynamic content.",
                "recommendation": "Encourage simple literal lists in install_requires or use a requirements.txt for scanning. If variables are used, ensure they are defined as simple literals near their use or add a pre-processing step in CI to render/runtime-evaluate dependency files safely."
            })

    return issues


RULES6 = [
    check_vulnerable_dependencies, #Known vulnerable library versions in requirements.txt or setup.py
]

'''
MEDIUM-HIGH
Missing version pinning (Flask without version)
Unsafe dependency inclusion (Direct import of deprecated or vulnerable modules (import xmlrpclib))
'''