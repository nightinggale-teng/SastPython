import ast

# === A08 Software and Data Integrity Failures ===

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
        
def check_pickle_load(node):
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ("load", "loads") and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A08 Software and Data Integrity Failures",
                "rule": "801",
                "vulnerability": "Insecure pickle.load / pickle.loads usage",
                "severity": "CRITICAL",
                "description": "The pickle.load / pickle.loads deserialize arbitrary Python objects and can execute attacker-controlled code during unpickling. Loading pickles from untrusted or tampered sources leads to Remote Code Execution (RCE).",
                "recommendation": "Never unpickle data from untrusted sources. Replace with safe formats (JSON, protobuf, MessagePack with safe loaders). If pickle must be used for internal/trusted data, authenticate and integrity-check inputs (e.g., signatures/HMAC) and restrict file access/permissions. Add tests and documentation for trust boundaries."
            }

# yaml.load without SafeLoader
def check_yaml_load(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 500:
            snippet = snippet[:500] + "..."
        if node.func.attr == "load" and isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
            safe_loader_used = any(
                isinstance(kw, ast.keyword)
                and kw.arg == "Loader"
                and isinstance(kw.value, ast.Attribute)
                and getattr(kw.value, "attr", "") == "SafeLoader"
                for kw in node.keywords
            )
            if not safe_loader_used:
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A08 Software and Data Integrity Failures",
                    "rule": "802",
                    "vulnerability": "Usage of yaml.load() without SafeLoader",
                    "severity": "CRITICAL",
                    "description": "The yaml.load() with the default loader can construct arbitrary Python objects (and execute constructors), enabling code execution when parsing attacker-controlled YAML.",
                    "recommendation": "Always use yaml.safe_load() or explicitly pass Loader=yaml.SafeLoader. If you must parse potentially unsafe YAML with richer features, parse into a restricted schema and validate all objects. Add CI checks to ensure safe loader usage."
                }
            
# marshal.load / marshal.loads
def check_marshal_load(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 500:
            snippet = snippet[:500] + "..."
        if node.func.attr in ("load", "loads") and isinstance(node.func.value, ast.Name) and node.func.value.id == "marshal":
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A08 Software and Data Integrity Failures",
                "rule": "803",
                "vulnerability": "Unsafe usage of marshal.load / marshal.loads",
                "severity": "CRITICAL",
                "description": "Marshal can deserialize Python bytecode and low-level objects; it’s not secure for untrusted data and can lead to unsafe behavior if input is tampered.",
                "recommendation": "Avoid accepting marshal payloads from untrusted sources. Use safe, documented serialization formats (JSON, protobuf). If you must accept marshal data, only load from trusted, integrity-protected locations and document the trust boundary."
            }

# dill.load / dill.loads
def check_dill_load(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 500:
            snippet = snippet[:500] + "..."
        if node.func.attr in ("load", "loads") and isinstance(node.func.value, ast.Name) and node.func.value.id == "dill":
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A08 Software and Data Integrity Failures",
                "rule": "804",
                "vulnerability": "Use of dill.load / dill.loads unsafe deserialization",
                "severity": "CRITICAL",
                "description": "The dill extends pickle-like behavior and can reconstruct arbitrary Python objects, so deserializing untrusted dill data can lead to RCE.",
                "recommendation": "Treat dill data as fully trusted only when origin is verified. Prefer safer serialization alternatives and verify signatures or checksums before loading."
            }

# cloudpickle.load / cloudpickle.loads
def check_cloudpickle_load(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 500:
            snippet = snippet[:500] + "..."
        if node.func.attr in ("load", "loads") and isinstance(node.func.value, ast.Name) and node.func.value.id == "cloudpickle":
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A08 Software and Data Integrity Failures",
                "rule": "805",
                "vulnerability": "Use of cloudpickle.load / cloudpickle.loads insecure deserialization",
                "severity": "CRITICAL",
                "description": "Cloudpickle can serialize and deserialize complex callables and objects; loading untrusted cloudpickle blobs can execute arbitrary code.",
                "recommendation": "Do not load cloudpickle blobs from untrusted sources. Validate provenance and integrity (signatures/HMAC). When distributing serialized models/artifacts, use secure storage and signed releases."
            }

# joblib.load / joblib.loadz
def check_joblib_load(node):
    # match joblib.load(...) calls
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    if node.func.attr not in ("load", "loadz"):   # keep your original attr choices
        return None
    if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "joblib"):
        return None

    # helper to decide if a node represents a literal filename (safe)
    def is_literal_filename(value_node):
        # Constant (py3.8+) with string/bytes
        if isinstance(value_node, ast.Constant):
            return isinstance(value_node.value, (str, bytes))
        # older ASTs may use ast.Str
        if isinstance(value_node, ast.Str):
            return True
        return False

    # helper to get code snippet
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."

    # 1) check first positional arg, if present
    if node.args:
        first = node.args[0]
        if is_literal_filename(first):
            return None   # safe: literal filename
        else:
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A08 Software and Data Integrity Failures",
                "rule": "806",
                "vulnerability": "Use joblib.load called with non-literal filename (unsafe input)",
                "severity": "CRITICAL",
                "description": "The joblib uses pickle under the hood. Passing a dynamic/untrusted path or object to joblib.load() risks loading attacker-controlled pickles.",
                "recommendation": "Only call joblib.load() with hard-coded or validated literal paths. If accepting path input, whitelist directories and validate filenames (no path traversal). Verify files with checksums or signatures before loading."
            }

    # 2) no positional args — check keyword args (commonly 'filename' or 'file')
    for kw in node.keywords:
        # skip kwargs like **kwargs where kw.arg is None
        if kw.arg is None:
            continue
        if kw.arg in ("filename", "file", "f", "fname", "path", "filepath"):
            if is_literal_filename(kw.value):
                return None  # safe
            else:
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A08 Software and Data Integrity Failures",
                    "rule": "806",
                    "vulnerability": "Use joblib.load called with non-literal filename (unsafe input)",
                    "severity": "CRITICAL",
                    "description": "The joblib uses pickle under the hood. Passing a dynamic/untrusted path or object to joblib.load() risks loading attacker-controlled pickles.",
                    "recommendation": "Only call joblib.load() with hard-coded or validated literal paths. If accepting path input, whitelist directories and validate filenames (no path traversal). Verify files with checksums or signatures before loading."
                }

    return None     # No args we can inspect — be conservative and do not raise (or optionally raise low severity)

# torch.load without valid filename
def check_torch_load(node):
    # match torch.load(...) calls
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    if node.func.attr != "load":
        return None
    if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "torch"):
        return None

    # Helper: decide if a node represents a (statically) literal filename or a literal-open call
    def is_literal_filename(value_node):
        # Constant (py3.8+) with string/bytes
        if isinstance(value_node, ast.Constant):
            return isinstance(value_node.value, (str, bytes))
        # older ASTs may use ast.Str
        if isinstance(value_node, ast.Str):
            return True
        # f-strings with only constant parts (JoinedStr -> all values Constant/Str)
        if isinstance(value_node, ast.JoinedStr):
            for part in getattr(value_node, "values", []):
                if not (isinstance(part, (ast.Constant, ast.Str))):
                    return False
            return True
        # open("literal.pt") -> treat as safe when first arg is literal
        if isinstance(value_node, ast.Call) and isinstance(value_node.func, ast.Name) and value_node.func.id == "open":
            if value_node.args:
                first = value_node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, (str, bytes)):
                    return True
                if isinstance(first, ast.Str):
                    return True
            return False
        return False

    # helper to get code snippet
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."

    # 1) check first positional arg, if present
    if node.args:
        first = node.args[0]
        if is_literal_filename(first):
            return None   # safe: literal filename or literal-open(...)
        else:
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A08 Software and Data Integrity Failures",
                "rule": "807",
                "vulnerability": "Use of torch.load called with non-literal filename / untrusted input",
                "severity": "CRITICAL",
                "description": "The torch.load() deserializes PyTorch objects using pickle. Passing a non-literal or attacker-controlled path can lead to execution of malicious code embedded in model files.",
                "recommendation": "Only load models from trusted, integrity-checked sources. Require literal or validated paths, verify digital signatures/checksums, use secure storage/ACLs, or load model weights using safe APIs (e.g., load state dict into known model architecture after validating format)."
            }

    # 2) check keyword args (commonly 'f' for the file)
    for kw in node.keywords:
        # skip kwargs like **kwargs where kw.arg is None
        if kw.arg is None:
            continue
        if kw.arg in ("f", "file", "filename", "path", "filepath"):
            if is_literal_filename(kw.value):
                return None  # safe
            else:
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A08 Software and Data Integrity Failures",
                    "rule": "807",
                    "vulnerability": "Use of torch.load called with non-literal filename / untrusted input",
                    "severity": "CRITICAL",
                    "description": "The torch.load() deserializes PyTorch objects using pickle. Passing a non-literal or attacker-controlled path can lead to execution of malicious code embedded in model files.",
                    "recommendation": "Only load models from trusted, integrity-checked sources. Require literal or validated paths, verify digital signatures/checksums, use secure storage/ACLs, or load model weights using safe APIs (e.g., load state dict into known model architecture after validating format)."
                }

    return None     # No inspectable args: conservatively don't flag (or change to low severity if you prefer)

# tf.saved_model.load
def check_tensorflow_load(node):
    # match tf.saved_model.load(...) calls
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    if node.func.attr != "load":
        return None
    # match tf.saved_model
    fn_value = node.func.value
    if not (isinstance(fn_value, ast.Attribute)
            and isinstance(fn_value.value, ast.Name)
            and fn_value.value.id == "tf"
            and fn_value.attr == "saved_model"):
        return None

    # Helper: decide if a node represents a statically literal/constant path
    def is_literal_path(value_node):
        # Constant (py3.8+) with string/bytes
        if isinstance(value_node, ast.Constant):
            return isinstance(value_node.value, (str, bytes))
        # older ASTs
        if isinstance(value_node, ast.Str):
            return True
        # f-strings with only constant parts
        if isinstance(value_node, ast.JoinedStr):
            for part in getattr(value_node, "values", []):
                # allow Constant/Str and formatted values that are Constant/Str
                if isinstance(part, ast.FormattedValue):
                    inner = part.value
                    if not (isinstance(inner, (ast.Constant, ast.Str))):
                        return False
                elif not isinstance(part, (ast.Constant, ast.Str)):
                    return False
            return True
        # os.path.join("a", "b") where all args are literal -> treat as literal
        if isinstance(value_node, ast.Call) and isinstance(value_node.func, ast.Attribute):
            fn = value_node.func
            # detect os.path.join(...) pattern
            if (fn.attr == "join"
                    and isinstance(fn.value, ast.Attribute)
                    and isinstance(fn.value.value, ast.Name)
                    and fn.value.value.id == "os"
                    and fn.value.attr == "path"):
                # check all args are literal strings
                for a in value_node.args:
                    if not is_literal_path(a):
                        return False
                return True
        return False

    # helper to get code snippet
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."

    # Inspect first positional arg
    if node.args:
        first = node.args[0]
        if is_literal_path(first):
            return None  # safe: literal path
        else:
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A08 Software and Data Integrity Failures",
                "rule": "808",
                "vulnerability": "Use of tf.saved_model.load with non-literal path (untrusted model loads)",
                "severity": "HIGH",
                "description": "Loading TensorFlow SavedModels from untrusted locations can execute code or load malicious graphs/ops; supplying dynamic/unvalidated paths increases the risk that a tampered model is loaded.",
                "recommendation": "Only load SavedModels from trusted, validated paths. Verify model integrity (checksums/signatures), and restrict permissions. Prefer internal model registries or signed artifacts for production loaders."
            }

    # Inspect common keyword arg names (conservative)
    for kw in node.keywords:
        if kw.arg is None:
            continue
        if kw.arg in ("export_dir", "saved_model_dir", "path", "dir", "filepath"):
            if is_literal_path(kw.value):
                return None
            else:
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A08 Software and Data Integrity Failures",
                    "rule": "808",
                    "vulnerability": "Use of tf.saved_model.load with non-literal path (untrusted model loads)",
                    "severity": "HIGH",
                    "description": "Loading TensorFlow SavedModels from untrusted locations can execute code or load malicious graphs/ops; supplying dynamic/unvalidated paths increases the risk that a tampered model is loaded.",
                    "recommendation": "Only load SavedModels from trusted, validated paths. Verify model integrity (checksums/signatures), and restrict permissions. Prefer internal model registries or signed artifacts for production loaders."
                }

    return None     # No inspectable args: don't flag (conservative)

# shelve.open with variable argument
def check_shelve_open(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 500:
            snippet = snippet[:500] + "..."
        if node.func.attr == "open" and isinstance(node.func.value, ast.Name) and node.func.value.id == "shelve":
            if node.args and not isinstance(node.args[0], ast.Constant):
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A08 Software and Data Integrity Failures",
                    "rule": "809",
                    "vulnerability": "Use shelve.open with untrusted argument (uses pickle internally)",
                    "severity": "CRITICAL",
                    "description": "Shelve stores/retrieves pickled objects. Opening a shelve file based on untrusted input can result in loading attacker-controlled pickles.",
                    "recommendation": "Require literal/whitelisted paths for shelve usage. Validate and sanitize filenames, avoid accepting paths from users, and prefer safer storage formats if data originates from untrusted sources."
                }

# dbm.open with variable argument
def check_dbm_open(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 500:
            snippet = snippet[:500] + "..."
        if node.func.attr == "open" and isinstance(node.func.value, ast.Name) and node.func.value.id == "dbm":
            if node.args and not isinstance(node.args[0], ast.Constant):
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A08 Software and Data Integrity Failures",
                    "rule": "810",
                    "vulnerability": "Use dbm.open with untrusted argument (unsafe deserialization risk)",
                    "severity": "HIGH",
                    "description": "Dbm or similar key-value persistence may involve loading data that can contain unsafe serialized content; opening DB files based on untrusted input risks processing tampered data.",
                    "recommendation": "Validate file paths; restrict to known directories and filenames. Use safe serialization formats and verify integrity before reading."
                }

# eval() or exec()
def check_eval_exec(node):
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in ("eval", "exec"):
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A08 Software and Data Integrity Failures",
                "rule": "811",
                "vulnerability": "Usage of eval() / exec() with untrusted data",
                "severity": "CRITICAL",
                "description": "The eval/exec execute Python code strings. If any portion of the evaluated string is attacker-controlled, this is remote code execution.",
                "recommendation": "Eliminate use of eval/exec on untrusted input. Use safe parsers (e.g., ast.literal_eval for literals), or implement a strict domain-specific language with a sandboxed interpreter. If unavoidable, heavily whitelist allowed expressions and run in a hardened sandbox process with least privileges."
            }

# pickle.loads(base64.b64decode(...))
def check_pickle_base64_combo(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "loads" and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
            if node.args and isinstance(node.args[0], ast.Call):
                inner = node.args[0]
                snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
                if len(snippet) > 500:
                    snippet = snippet[:500] + "..."
                if isinstance(inner.func, ast.Attribute):
                    if inner.func.attr == "b64decode" and isinstance(inner.func.value, ast.Name) and inner.func.value.id == "base64":
                        return {
                            "line": node.lineno,
                            "function": snippet,
                            "category": "A08 Software and Data Integrity Failures",
                            "rule": "812",
                            "vulnerability": "Use of pickle.loads(base64.b64decode()) encoded deserialization pattern",
                            "severity": "CRITICAL",
                            "description": "Encoding pickled payloads (e.g., base64) doesn't make them safe—this pattern is often used to hide payloads and still leads to unsafe deserialization and RCE.",
                            "recommendation": "Treat encoded pickles as equally dangerous. Disallow or explicitly verify encoded payloads before decoding. Use safe formats and authenticate any encoded payloads (signatures/HMAC)."
                        }

# Custom __reduce__ or __setstate__ methods
def check_custom_reduce(node):
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."
    if isinstance(node, ast.FunctionDef) and node.name in ("__reduce__", "__setstate__"):
        return {
            "line": node.lineno,
            "function": snippet,
            "category": "A08 Software and Data Integrity Failures",
            "rule": "813",
            "vulnerability": "Custom __reduce__ / __setstate__ methods present in code",
            "severity": "HIGH",
            "description": "Custom __reduce__ / __setstate__ implementations control how objects are pickled/unpickled and can be abused to perform arbitrary actions on unpickling, increasing attack surface for crafted pickles.",
            "recommendation": "Audit and minimize use of custom reduce/setstate implementations. If present, document and constrain their behavior; ensure unpickling only occurs for trusted data and add unit tests validating expected behavior. Consider alternate safe serialization for public interfaces."
        }
                        
RULES8 = [
    check_pickle_load,
    check_yaml_load,
    check_marshal_load,
    check_dill_load,
    check_cloudpickle_load,
    check_joblib_load,
    check_torch_load,
    check_tensorflow_load,
    check_shelve_open,
    check_dbm_open,
    check_eval_exec,
    check_pickle_base64_combo,
    check_custom_reduce,
]

'''
CRITICAL
Insecure deserialization using pickle.load() / pickle.loads()
Unsafe marshal or shelve loading (marshal.load())
Unvalidated YAML deserialization (yaml.load() without SafeLoader)
Untrusted joblib loading (joblib.load())
Unsafe cloud model loading (tf.saved_model.load(user_input))
Unverified signed data and integrity verification (no digital signature or checksum check)
'''