import ast

# === A03 Injection ===

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
                                               
def check_eval_exec(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 400:
            snippet = snippet[:400] + "..."
        if node.func.id in {"eval", "exec"}:
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A03 Injection",
                "rule": "301",
                "vulnerability": "Dynamic code execution via eval() / exec()",
                "severity": "CRITICAL",
                "description": "Calling eval() or exec() executes arbitrary Python code built at runtime. If any portion of their input is influenced by an attacker (user input, request data, untrusted files), it leads to remote code execution (RCE). builtins.eval() is equivalent and also dangerous.",
                "recommendation": "Remove uses of eval()/exec(). Replace with safe alternatives: parse structured input (JSON), use ast.literal_eval() for simple literal parsing, or implement clearly-defined interpreters for allowed operations. If dynamic behaviour is unavoidable, strictly whitelist allowed operations and never pass user-controlled strings directly to eval/exec."
            }
        
def check_compile_exec(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 400:
            snippet = snippet[:400] + "..."
        if node.func.id == "compile":
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A03 Injection",
                "rule": "302",
                "vulnerability": "compile() used to create dynamic code",
                "severity": "CRITICAL",
                "description": "compile() can compile and then execute injected code (via exec()/eval() or exec(compile(...))). It enables dynamic code execution and therefore RCE when input is attacker-controlled.",
                "recommendation": "Avoid compiling untrusted strings. If you must generate code, use safe templates that never include raw user input, or use a sandboxed language/runtime designed for safe evaluation. Prefer structured data formats or whitelisted operations."
            }

def check_builtins_eval(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 400:
            snippet = snippet[:400] + "..."
        if isinstance(node.func.value, ast.Name) and node.func.value.id == "builtins" and node.func.attr == "eval":
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A03 Injection",
                "rule": "301",
                "vulnerability": "Dynamic code execution via eval() / exec()",
                "severity": "CRITICAL",
                "description": "Calling eval() or exec() executes arbitrary Python code built at runtime. If any portion of their input is influenced by an attacker (user input, request data, untrusted files), it leads to remote code execution (RCE). builtins.eval() is equivalent and also dangerous.",
                "recommendation": "Remove uses of eval()/exec(). Replace with safe alternatives: parse structured input (JSON), use ast.literal_eval() for simple literal parsing, or implement clearly-defined interpreters for allowed operations. If dynamic behaviour is unavoidable, strictly whitelist allowed operations and never pass user-controlled strings directly to eval/exec."
            }

SUBPROCESS_FUNCTIONS = {"Popen", "call", "check_call", "check_output", "run"}

def check_subprocess_insecure_with_alias(node, analyzer=None):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    
    func = node.func
    if isinstance(func.value, ast.Name):
        invoked_name = func.value.id  # e.g., 'sp' or 'subprocess'
        module_name = None  # resolve module name from imports
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 400:
            snippet = snippet[:400] + "..."
        if analyzer and hasattr(analyzer, "import_aliases"):
            module_name = analyzer.import_aliases.get(invoked_name, None)
        if module_name is None:
            module_name = invoked_name  # also accept direct 'subprocess'
        if module_name == "subprocess" and func.attr in SUBPROCESS_FUNCTIONS:
            func_name = func.attr            
            for kw in node.keywords:    # shell=True check
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A03 Injection",
                        "rule": "303",
                        "vulnerability": "Subprocess invocation with shell=True",
                        "severity": "HIGH",
                        "description": "Running subprocess.*(..., shell=True) passes the command to the shell, which interprets shell metacharacters — this allows command injection if user data is interpolated into the command.",
                        "recommendation": "Use argument lists and shell=False (the default). If shell=True is absolutely required, never include user input in the command string; escape/quote inputs with shlex.quote and prefer strict whitelists."
                    }
            if node.args:   # analyze first arg
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A03 Injection",
                        "rule": "304",
                        "vulnerability": "Subprocess called with a single string literal (not list form)",
                        "severity": "MEDIUM",
                        "description": "Passing a string command literal to subprocess APIs is fragile and usually indicates shell-style execution. Even if the literal is constant, it’s better practice to use the list form to avoid accidental shell interpretation or later introduction of interpolation.",
                        "recommendation": "Prefer [\"program\", \"arg1\", \"arg2\"] list form for subprocess calls to avoid the shell and make argument boundaries explicit."
                    }
                if isinstance(first, (ast.JoinedStr, ast.BinOp, ast.FormattedValue, ast.Name, ast.Call)):
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A03 Injection",
                        "rule": "305",
                        "vulnerability": "Subprocess called with constructed/non-constant commands (f-strings, concatenation, formatting, or variables)",
                        "severity": "HIGH",
                        "description": "Commands built by string concatenation, f-strings or by passing variables to a subprocess string lead to command injection when variables are attacker-controlled.",
                        "recommendation": "Use an argument list and avoid building a single command string. If you must assemble some pieces, validate/whitelist each piece (allowed binaries/flags), or use shlex.quote for every user-controlled chunk and prefer subprocess lists."
                    }
    return None

def check_shell_and_exec_calls(node, analyzer=None):
    if not isinstance(node, ast.Call):
        return None
    
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."

    SHELL_INVOCATORS = {       # helpers lists (full dotted names as strings)
        "os.system",
        "os.popen",
        "os.popen2",           # legacy
        "os.popen3",
        "os.popen4",
        "popen2.popen2",       # legacy module patterns
        "popen2.popen3",
        "popen2.Popen3",
        "popen2.Popen4",
        "commands.getoutput",  # python2 legacy
        "commands.getstatusoutput",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }

    EXEC_FAMILY = {             # not classic shell injection, but still risky
        "os.execl", "os.execle", "os.execlp", "os.execlpe",
        "os.execv", "os.execve", "os.execvp", "os.execvpe",
        "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
        "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
        "os.startfile",
    }

    def get_callee_dotted_name(func_node):  # helper to extract dotted name from ast.Attribute / ast.Name
        parts = []
        n = func_node
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if isinstance(n, ast.Name):
            parts.append(n.id)
        elif isinstance(n, ast.Call):
            return None                     # something like foo().bar — treat as unknown
        else:
            return None
        return ".".join(reversed(parts))    # parts were collected from right-to-left, reverse and join

    if isinstance(node.func, ast.Attribute):    # attribute like os.system or subprocess.getoutput
        dotted = get_callee_dotted_name(node.func)
        if dotted is None:
            return None
        parts = dotted.split(".")               # resolve left-most identifier via import aliases where appropriate
        if len(parts) >= 2:
            left = parts[0]
            rest = ".".join(parts[1:])
            resolved_left = left
            if analyzer and hasattr(analyzer, "import_aliases"):
                resolved_left = analyzer.import_aliases.get(left, left)
            resolved = f"{resolved_left}.{rest}"
        else:
            resolved = dotted

        if resolved in SHELL_INVOCATORS:
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A03 Injection",
                "rule": "306",
                "vulnerability": "Shell invocations via os.system, os.popen, legacy popen2/commands, subprocess.getoutput (shell-invoking helpers)",
                "severity": "HIGH",
                "description": "These helpers send strings to a shell or provide easier access to shell execution, exposing the same command-injection risk as shell=True. Many are legacy and less safe.",
                "recommendation": "Replace with subprocess.run([...]) or subprocess.check_output([...]) with a list of args and shell=False. Remove usage of legacy modules."
            }
        if resolved in EXEC_FAMILY:
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A03 Injection",
                "rule": "307",
                "vulnerability": "Exec-family (os.exec*, os.spawn*, os.startfile) cause direct program execution risk",
                "severity": "MEDIUM",
                "description": "These functions execute programs directly. They are not parsed by a shell, but unvalidated or unsanitized arguments can still cause privilege escalation, unintended behavior, or allow execution of attacker-supplied binaries.",
                "recommendation": "Validate and whitelist executable paths and arguments, avoid passing user-supplied file paths or program names directly. Use absolute paths and perform checks (ownership, permissions) where appropriate."
            }

    if isinstance(node.func, ast.Name):                 # function likely from `from X import Y` or direct import alias
        name = node.func.id
        if analyzer and hasattr(analyzer, "import_aliases"):
            mapped = analyzer.import_aliases.get(name)  # handle module-level calls if name maps to a module

            if mapped:                                  # direct mapping to module is rare for calls
                possible_full = f"{mapped}.{name}"
                if possible_full in SHELL_INVOCATORS:
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A03 Injection",
                        "rule": "306",
                        "vulnerability": "Shell invocations via os.system, os.popen, legacy popen2/commands, subprocess.getoutput (shell-invoking helpers)",
                        "severity": "HIGH",
                        "description": "These helpers send strings to a shell or provide easier access to shell execution, exposing the same command-injection risk as shell=True. Many are legacy and less safe.",
                        "recommendation": "Replace with subprocess.run([...]) or subprocess.check_output([...]) with a list of args and shell=False. Remove usage of legacy modules."
                    }

            origin = analyzer.import_aliases.get(name)  # name was imported from a module
            if origin:
                dotted = f"{origin}.{name}"
                if dotted in SHELL_INVOCATORS:
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A03 Injection",
                        "rule": "306",
                        "vulnerability": "Shell invocations via os.system, os.popen, legacy popen2/commands, subprocess.getoutput (shell-invoking helpers)",
                        "severity": "HIGH",
                        "description": "These helpers send strings to a shell or provide easier access to shell execution, exposing the same command-injection risk as shell=True. Many are legacy and less safe.",
                        "recommendation": "Replace with subprocess.run([...]) or subprocess.check_output([...]) with a list of args and shell=False. Remove usage of legacy modules."
                    }
                if dotted in EXEC_FAMILY:
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A03 Injection",
                        "rule": "307",
                        "vulnerability": "Exec-family (os.exec*, os.spawn*, os.startfile) cause direct program execution risk",
                        "severity": "MEDIUM",
                        "description": "These functions execute programs directly. They are not parsed by a shell, but unvalidated or unsanitized arguments can still cause privilege escalation, unintended behavior, or allow execution of attacker-supplied binaries.",
                        "recommendation": "Validate and whitelist executable paths and arguments, avoid passing user-supplied file paths or program names directly. Use absolute paths and perform checks (ownership, permissions) where appropriate."
                    }

def check_pickle_load(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 400:
            snippet = snippet[:400] + "..."
        if node.func.attr == "load" and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A03 Injection",
                "rule": "308",
                "vulnerability": "Usage of pickle.load() (untrusted deserialization)",
                "severity": "CRITICAL",
                "description": "Pickle can execute arbitrary code during deserialization (via __reduce__, etc.). Loading pickled data from untrusted sources leads to remote code execution.",
                "recommendation": "Never unpickle data from untrusted sources. Use safe serialization formats (JSON, MessagePack with safe loaders) or other safe libraries. If you must use pickle for trusted internal data, ensure transport is authenticated and integrity-protected (e.g., signed tokens), and document the trust boundary."
            }

SQL_EXEC_FUNCS = {"execute", "executemany", "executescript"}

# common taint source function/attribute names
TAINT_CALL_NAMES = {
    "input",
    "raw_input",  # py2
}
TAINT_ATTR_PATTERNS = (
    ("request", "args"),
    ("request", "form"),
    ("request", "json"),
    ("request", "get_json"),
    ("request", "values"),
    ("flask", "request"),
    ("self", "request"),
    ("sys", "argv"),
    ("sys", "stdin"),
)

def _is_string_concatenation_like(node):
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True
    return False

def _find_assignment_for_name(source_code, name):
    try:
        tree = ast.parse(source_code)
    except Exception:
        return None
    assigned_node = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    assigned_node = node.value
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            assigned_node = node.value
    return assigned_node

def _is_name_function_param(source_code, name):
    """Return True if `name` appears as a parameter name in any function definition."""
    try:
        tree = ast.parse(source_code)
    except Exception:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if arg.arg == name:
                    return True
            # also check kwonly args and positional-only (py3.8+)
            for arg in getattr(node.args, "kwonlyargs", []):
                if arg.arg == name:
                    return True
            for arg in getattr(node.args, "posonlyargs", []):
                if arg.arg == name:
                    return True
    return False

def _call_is_taint_source(call_node):
    """
    Heuristic: detect calls that are likely taint sources, e.g. request.args.get(...), input(), sys.argv[...] etc.
    """
    if call_node is None or not isinstance(call_node, ast.Call):
        return False

    # direct name calls like input()
    if isinstance(call_node.func, ast.Name):
        if call_node.func.id in TAINT_CALL_NAMES:
            return True

    # attribute-style calls like request.args.get()
    if isinstance(call_node.func, ast.Attribute):
        # build dotted parts into a list, right-to-left
        parts = []
        n = call_node.func
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if isinstance(n, ast.Name):
            parts.append(n.id)
        parts = list(reversed(parts))  # left-to-right

        # check patterns like ("request", "args", "get") or ("request","form","get")
        if len(parts) >= 2:
            for pat in TAINT_ATTR_PATTERNS:
                if tuple(parts[:len(pat)]) == pat:
                    return True

        # also catch request.get_json() style single attr pattern
        if len(parts) >= 1 and tuple(parts[:1]) == ("request",):
            # e.g., request.get_json()
            return True

    return False

def _call_has_params(call_node):
    """
    Heuristic: treat call as parameterized (safe) if second positional arg present
    or keyword param typical for param passing is present.
    """
    if not isinstance(call_node, ast.Call):
        return False
    if len(call_node.args) >= 2:
        return True
    param_kw_names = {"params", "parameters", "args", "values", "params_"}
    for kw in call_node.keywords:
        if kw.arg and kw.arg.lower() in param_kw_names:
            return True
        if isinstance(kw.value, (ast.Tuple, ast.List, ast.Dict)):
            return True
    return False

def check_sql_string_concatenation(node, analyzer=None, **kwargs):
    """
    Detect SQL queries constructed via concatenation/f-string/.format() passed to execute()
    and detect session.execute(text(user_sql)) patterns where user_sql is likely tainted.
    """
    if not isinstance(node, ast.Call):
        return None
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 400:
        snippet = snippet[:400] + "..."

    # Extract function name being called (cur.execute / session.execute / execute)
    func = node.func
    func_name = None
    if isinstance(func, ast.Attribute):
        func_name = func.attr
    elif isinstance(func, ast.Name):
        func_name = func.id

    if func_name not in SQL_EXEC_FUNCS:
        return None

    # If call appears parameterized, skip (we treat as safe)
    if _call_has_params(node):
        return None

    # Must have at least one positional arg (the SQL or text(...) wrapper)
    if not node.args:
        return None
    first_arg = node.args[0]

    # 1) direct concatenation / f-string / .format() inline
    if _is_string_concatenation_like(first_arg):
        return {
            "line": node.lineno,
            "function": snippet,
            "category": "A03 Injection",
            "rule": "309",
            "vulnerability": "SQL execution via string concatenation / f-strings / .format() (unparameterized SQL)",
            "severity": "HIGH",
            "description": "Building SQL queries via string concatenation or f-strings and passing them to execute() lets an attacker inject SQL (SQL injection). Even session.execute(text(...)) with user SQL is dangerous.",
            "recommendation": "Always use parameterized queries / prepared statements (DB-API parameter placeholders or SQLAlchemy parameterization). Never interpolate user input into SQL strings. If you must build dynamic SQL structure (e.g., column names), whitelist allowed tokens and use parameterization for values."
        }

    # 2) handle session.execute(text(...)) and other wrappers
    # case: session.execute(text(user_sql)) or session.execute(text("..."+var...))
    if isinstance(first_arg, ast.Call):
        # text(...) can be ast.Name or ast.Attribute depending on import style
        inner_call = first_arg
        # If the wrapper function is named "text" (common SQLAlchemy pattern) OR attribute .text
        wrapper_name = None
        if isinstance(inner_call.func, ast.Name):
            wrapper_name = inner_call.func.id
        elif isinstance(inner_call.func, ast.Attribute):
            wrapper_name = inner_call.func.attr

        if wrapper_name == "text":
            # inspect the first argument passed into text(...)
            if not inner_call.args:
                return None
            inner = inner_call.args[0]

            # inner is an inline concatenation or f-string -> flag
            if _is_string_concatenation_like(inner):
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A03 Injection",
                    "rule": "309",
                    "vulnerability": "SQL execution via string concatenation / f-strings / .format() (unparameterized SQL)",
                    "severity": "HIGH",
                    "description": "Building SQL queries via string concatenation or f-strings and passing them to execute() lets an attacker inject SQL (SQL injection). Even session.execute(text(...)) with user SQL is dangerous.",
                    "recommendation": "Always use parameterized queries / prepared statements (DB-API parameter placeholders or SQLAlchemy parameterization). Never interpolate user input into SQL strings. If you must build dynamic SQL structure (e.g., column names), whitelist allowed tokens and use parameterization for values."
                }

            # inner is a direct call to a taint source -> flag
            if isinstance(inner, ast.Call) and _call_is_taint_source(inner):
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A03 Injection",
                    "rule": "310",
                    "vulnerability": "session.execute(text(user_sql)) or execute(text(...)) where text(...) argument comes from taint sources",
                    "severity": "HIGH",
                    "description": "Wrapping user-controlled SQL in text() and passing to execute is the same as running raw SQL — it bypasses parameterization and allows arbitrary SQL injection, especially when the text comes directly/indirectly from request parameters or function parameters.",
                    "recommendation": "Disallow passing user-supplied SQL. If you need to allow user-specified queries, run them only in a strict sandboxed environment with read-only permissions or use a safe query builder with whitelists. Prefer parameterized queries and check if the SQL string originates from untrusted sources."
                }

            # inner is a Name (variable), check if that variable is suspicious:
            if isinstance(inner, ast.Name) and analyzer and hasattr(analyzer, "source_code"):
                var_name = inner.id
                src = analyzer.source_code

                # If variable is a function parameter, likely user-controlled -> flag
                if _is_name_function_param(src, var_name):
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A03 Injection",
                        "rule": "310",
                        "vulnerability": "session.execute(text(user_sql)) or execute(text(...)) where text(...) argument comes from taint sources",
                        "severity": "HIGH",
                        "description": "Wrapping user-controlled SQL in text() and passing to execute is the same as running raw SQL — it bypasses parameterization and allows arbitrary SQL injection, especially when the text comes directly/indirectly from request parameters or function parameters.",
                        "recommendation": "Disallow passing user-supplied SQL. If you need to allow user-specified queries, run them only in a strict sandboxed environment with read-only permissions or use a safe query builder with whitelists. Prefer parameterized queries and check if the SQL string originates from untrusted sources."
                    }

                # If variable was assigned from a taint source earlier -> flag
                assigned_node = _find_assignment_for_name(src, var_name)
                if isinstance(assigned_node, ast.Call) and _call_is_taint_source(assigned_node):
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A03 Injection",
                        "rule": "310",
                        "vulnerability": "session.execute(text(user_sql)) or execute(text(...)) where text(...) argument comes from taint sources",
                        "severity": "HIGH",
                        "description": "Wrapping user-controlled SQL in text() and passing to execute is the same as running raw SQL — it bypasses parameterization and allows arbitrary SQL injection, especially when the text comes directly/indirectly from request parameters or function parameters.",
                        "recommendation": "Disallow passing user-supplied SQL. If you need to allow user-specified queries, run them only in a strict sandboxed environment with read-only permissions or use a safe query builder with whitelists. Prefer parameterized queries and check if the SQL string originates from untrusted sources."
                    }

                # If variable assignment is concatenation-like -> flag
                if _is_string_concatenation_like(assigned_node):
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A03 Injection",
                        "rule": "312",
                        "vulnerability": "Constructed SQL stored in variables from taint sources or concatenation",
                        "severity": "HIGH",
                        "description": "When a variable assigned earlier (e.g., function parameter, or value from request) is used as the SQL argument to execute() (especially via text()), it's a likely SQL injection vector. The analyzer flags patterns where variable assignments come from tainted sources or concatenation.",
                        "recommendation": "Trace origin of query variables; require that variables used for SQL are either parameterized values or come from safe, whitelisted templates. If dynamic SQL fragments are needed (e.g., dynamic ORDER BY), validate them strictly against allowed values."
                    }

    # 3) If first_arg is a Name directly (e.g., session.execute(q)) we already handle variable lookup above for concatenation-like
    if isinstance(first_arg, ast.Name) and analyzer and hasattr(analyzer, "source_code"):
        var_name = first_arg.id
        assigned = _find_assignment_for_name(analyzer.source_code, var_name)
        if isinstance(assigned, ast.Call) and _call_is_taint_source(assigned):
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A03 Injection",
                "rule": "311",
                "vulnerability": "Taint sources not sanitized (input(), raw_input(), request.args, request.form, request.json, sys.argv, sys.stdin)",
                "severity": "HIGH",
                "description": "These calls bring data directly from users or the environment. If that data flows into eval/exec/subprocess/SQL/pickle without validation or santization it creates injection or RCE risks.",
                "recommendation": "Treat all such data as tainted. Apply validation, canonicalization, strict length/type checks, and preferably use whitelisting. Use parameterization for SQL, avoid direct execution, and apply escaping only as a last resort."
            }
        if _is_string_concatenation_like(assigned):
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A03 Injection",
                "rule": "312",
                "vulnerability": "Constructed SQL stored in variables from taint sources or concatenation",
                "severity": "HIGH",
                "description": "When a variable assigned earlier (e.g., function parameter, or value from request) is used as the SQL argument to execute() (especially via text()), it's a likely SQL injection vector. The analyzer flags patterns where variable assignments come from tainted sources or concatenation.",
                "recommendation": "Trace origin of query variables; require that variables used for SQL are either parameterized values or come from safe, whitelisted templates. If dynamic SQL fragments are needed (e.g., dynamic ORDER BY), validate them strictly against allowed values."
            }

    return None

RULES3 = [
    check_eval_exec,
    check_compile_exec,
    check_builtins_eval,
    check_subprocess_insecure_with_alias,
    check_shell_and_exec_calls,
    check_sql_string_concatenation,
]

'''
CRITICAL
Code injection (Use of eval(), exec(), or compile() on untrusted input)
Command injection (via os.system() or subprocess.Popen(user_input))
Sql injection (using string concatenation in queries)
Template injection (e.g., render_template_string(user_input))
'''