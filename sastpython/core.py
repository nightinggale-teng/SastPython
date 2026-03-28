from __future__ import annotations
import ast
import inspect
import logging
from typing import Any, Optional
from sastpython.rules1 import RULES1
from sastpython.rules2 import RULES2
from sastpython.rules3 import RULES3
from sastpython.rules5 import RULES5
from sastpython.rules6 import RULES6, run_rules6_on_ast
from sastpython.rules8 import RULES8

class SecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, source_code):
        self.source_code = source_code
        self.source_tree = ast.parse(self.source_code)
        self.issues = []
        self.import_aliases = {}
        self.all_rules = RULES1 + RULES2 + RULES3 + RULES5 + RULES6 + RULES8

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self.import_aliases[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self.import_aliases[name] = module
        self.generic_visit(node)

    def generic_visit(self, node):
        for rule in self.all_rules:
            try:
                sig = inspect.signature(rule)
                if "analyzer" in sig.parameters:
                    issue = rule(node, analyzer=self)
                else:
                    issue = rule(node)
                if issue:
                    self.issues.append(issue)
            except Exception:
                pass    # fail-safe: rule should never break analysis
        super().generic_visit(node)
    
def visit(self, node: ast.AST) -> Optional[Any]:
    # If this is the module root, do full traversal then run RULES6 walker:
    if isinstance(node, ast.Module):
        super().visit(node)
        try:
            raw_extra = run_rules6_on_ast(node, analyzer=self)
            extra_issues = self._flatten_and_normalize_issues(raw_extra)
            if extra_issues:
                self.issues.extend(extra_issues)
        except Exception as e:
            logging.exception("run_rules6_on_ast failed: %s", e)
            self.issues.append({
                "line": 0,
                "severity": "ERROR",
                "message": f"Internal rules6 AST analysis failed: {e}"
            })
        return None

    return super().visit(node)