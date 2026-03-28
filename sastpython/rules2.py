import ast
import re

# === A02 Cryptographic Failures ===

SUSPICIOUS_KEYS = {"password", "pass", "passwd", "pwd", "secret", "secret_token", "api_key", "token", "credentials"}
        
def check_hardcoded_secret(node):
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in SUSPICIOUS_KEYS:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    return {
                        "line": node.lineno,
                        "function": target.id,
                        "category": "A02 Cryptographic Failures",
                        "rule": "201",
                        "vulnerability": "Hardcoded secret in variable",
                        "severity": "HIGH",
                        "description": "Secret values (password, token, api_key, etc.) are embedded directly in source code variables, which risks accidental leakage (VCS, builds, logs).",
                        "recommendation": "Stop committing secrets to source. Load secrets from environment variables or a secret manager (Vault, AWS Secrets Manager, GCP Secret Manager). Rotate exposed secrets and add pre-commit/Git hooks to block committed secrets."
                    }
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
        
def check_db_url(node):
    if isinstance(node, ast.Assign):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            snippet = safe_unparse(node.value)
            if snippet is None:
                snippet = value[:400]
            else:
                snippet = snippet.strip()[:400]
            # Look for URI with user:pass@host
            if re.search(r"://[^:]+:[^@]+@", value):
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A02 Cryptographic Failures",
                    "rule": "202",
                    "vulnerability": "Embedded credentials in DB connection string",
                    "severity": "HIGH",
                    "description": "Connection URI contains user:pass@host, exposing credentials in code or config files. This leaks DB credentials to repos, logs, and backups.",
                    "recommendation": "Use environment variables, configuration stores, or credential providers. Use driver-specific authentication (IAM, managed identities) or place credentials in a vault, never inline in URIs."
                }

def check_dict_hardcoded_credentials(node):
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
        for key, val in zip(node.value.keys, node.value.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if key.value.lower() in SUSPICIOUS_KEYS:
                    if isinstance(val, ast.Constant) and isinstance(val.value, str):
                        snippet = safe_unparse(node)
                        return {
                            "line": node.lineno,
                            "function": snippet.strip()[:400],
                            "category": "A02 Cryptographic Failures",
                            "rule": "203",
                            "vulnerability": "Hardcoded credential in dictionary literal",
                            "severity": "HIGH",
                            "description": "Strings assigned inside dicts (e.g., {\"password\": \"...\"}) hold secrets in plaintext in code/config.",
                            "recommendation": "Move credential values to protected config backends or environment variables; validate and scan codebases for such patterns and rotate any exposed values."
                        }

def check_function_defaults(node):
    if isinstance(node, ast.FunctionDef):
        for arg, default in zip(node.args.args[-len(node.args.defaults):], node.args.defaults):
            if isinstance(default, ast.Constant) and isinstance(default.value, str):
                if arg.arg.lower() in SUSPICIOUS_KEYS or "pass" in arg.arg.lower():
                    snippet = safe_unparse(node).strip()[:400]
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A02 Cryptographic Failures",
                        "rule": "204",
                        "vulnerability": "Hardcoded default secret in function parameter",
                        "severity": "HIGH",
                        "description": "Sensitive defaults in function signatures (e.g., def foo(password=\"...\")) bake credentials into the API surface and docs.",
                        "recommendation": "Remove defaults for secrets. Require explicit passing of secret handles or fetch from secure stores at runtime."
                    }

def check_class_secrets(node):
    if isinstance(node, ast.Assign):
        if isinstance(node.targets[0], ast.Attribute) and isinstance(node.targets[0].attr, str):
            if node.targets[0].attr.lower() in SUSPICIOUS_KEYS:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    snippet = safe_unparse(node).strip()[:400]
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A02 Cryptographic Failures",
                        "rule": "205",
                        "vulnerability": "Hardcoded secret as class attribute",
                        "severity": "HIGH",
                        "description": "Class-level attributes named like secret/api_key set to string constants store secrets in code and runtime objects.",
                        "recommendation": "Load secrets at instance creation from secure stores; use configuration injection and restrict object serialization/logging."
                    }

WEAK_RANDOM_FUNCTIONS = {
    ("random", "random"),
    ("random", "randint"),
    ("random", "randrange"),
    ("random", "choice"),
    ("random", "uniform"),
    ("uuid", "uuid4"),
    ("time", "time"),
    ("numpy.random", "rand"),
    ("numpy.random", "randint"),
    ("numpy.random", "random"),
    ("numpy.random", "choice"),
}

PREDICTABLE_KEYWORDS = {"token", "key", "password", "secret", "session"}
INCREMENTAL_SOURCES = {"id", "counter", "count", "index", "num", "i", "n"}

def check_weak_randomness(node, analyzer=None):
    """Detect weak randomness, insecure seeding, and predictable token generation."""
    if not isinstance(node, ast.Call):
        # Detect f-string or string concatenation constructing predictable tokens
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.JoinedStr, ast.BinOp)):
            # Check if variable name looks like a security-sensitive token
            for target in node.targets:
                if isinstance(target, ast.Name):
                    varname = target.id.lower()
                    if any(k in varname for k in PREDICTABLE_KEYWORDS):
                        # f-string tokens like f"TOKEN-{user_id}-{counter}"
                        if isinstance(node.value, ast.JoinedStr):
                            for value in node.value.values:
                                if isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name):
                                    name = value.value.id.lower()
                                    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
                                    if len(snippet) > 400:
                                        snippet = snippet[:400] + "..."
                                    if name in INCREMENTAL_SOURCES:
                                        return {
                                            "line": node.lineno,
                                            "function": snippet,
                                            "category": "A02 Cryptographic Failures",
                                            "rule": "206",
                                            "vulnerability": "Predictable token constructed from incremental inputs (f-string / concatenation)",
                                            "severity": "HIGH",
                                            "description": "Tokens built from predictable variables (ids, counters, timestamps) are guessable and can be exploited to impersonate sessions or reuse tokens.",
                                            "recommendation": "Generate unpredictable tokens with a CSPRNG (e.g., secrets.token_urlsafe() / secrets.token_bytes()), and avoid encoding incremental IDs into tokens."
                                        }
                        # String concatenation like "TOKEN-" + user_id + str(counter)
                        if isinstance(node.value, ast.BinOp):
                            names = [
                                n.id.lower() for n in ast.walk(node.value)
                                if isinstance(n, ast.Name)
                            ]
                            if any(n in INCREMENTAL_SOURCES for n in names):
                                snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
                                if len(snippet) > 400:
                                    snippet = snippet[:400] + "..."
                                return {
                                    "line": node.lineno,
                                    "function": snippet,
                                    "category": "A02 Cryptographic Failures",
                                    "rule": "206",
                                    "vulnerability": "Predictable token constructed from incremental inputs (f-string / concatenation)",
                                    "severity": "HIGH",
                                    "description": "Tokens built from predictable variables (ids, counters, timestamps) are guessable and can be exploited to impersonate sessions or reuse tokens.",
                                    "recommendation": "Generate unpredictable tokens with a CSPRNG (e.g., secrets.token_urlsafe() / secrets.token_bytes()), and avoid encoding incremental IDs into tokens."
                                }

        return None

    func = node.func

    # --- Case 1: Weak randomness functions ---
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        module = func.value.id
        name = func.attr
        full_name = (module, name)
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 400:
            snippet = snippet[:400] + "..."

        if analyzer and hasattr(analyzer, "import_aliases"):
            real_module = analyzer.import_aliases.get(module, module)
            full_name = (real_module, name)

        if full_name in WEAK_RANDOM_FUNCTIONS:
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A02 Cryptographic Failures",
                "rule": "207",
                "vulnerability": "Use of weak PRNG functions for security-sensitive values",
                "severity": "MEDIUM",
                "description": "Calls to random.random()/randint()/choice(), numpy.random, uuid4() (per your rule set), or other non-cryptographic RNGs are unsuitable for keys, tokens or secrets.",
                "recommendation": "Use Python's secrets module for token/key generation, or os.urandom()/secrets for bytes. Reserve random/numpy.random for non-security uses like simulations."
            }

        # --- Case 2: Insecure seeding ---
        if full_name == ("random", "seed"):
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                    if isinstance(arg.func.value, ast.Name) and arg.func.value.id == "os" and arg.func.attr == "urandom":
                        return {
                            "line": node.lineno,
                            "function": snippet,
                            "category": "A02 Cryptographic Failures",
                            "rule": "209",
                            "vulnerability": "Mixing secure and insecure randomness (insecure seeding with os.urandom)",
                            "severity": "MEDIUM",
                            "description": "Combining random.seed(os.urandom()) mixes secure entropy into an insecure PRNG; result may be misused as secure randomness but inherits PRNG weaknesses.",
                            "recommendation": "Avoid mixing; use secure functions (secrets, os.urandom) directly for cryptographic needs."
                        }
                if isinstance(arg, ast.Constant):
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A02 Cryptographic Failures",
                        "rule": "208",
                        "vulnerability": "Static or predictable seeding of PRNG",
                        "severity": "HIGH",
                        "description": "Using a constant seed (e.g., random.seed(1234)) makes RNG outputs deterministic and predictable.",
                        "recommendation": "Remove static seeds for any security use. If seeding is required for reproducible tests, isolate test code from production; never seed security RNGs with fixed values."
                    }

        # --- Case 3: os.urandom misuse ---
        if full_name == ("os", "urandom"):
            parent = getattr(node, "parent", None)
            if parent and isinstance(parent, ast.Call) and isinstance(parent.func, ast.Attribute):
                if parent.func.attr in {"hex", "b64encode"}:
                    return None  # safe
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A02 Cryptographic Failures",
                "rule": "210",
                "vulnerability": "os.urandom() misuse or ambiguous usage",
                "severity": "LOW",
                "description": "os.urandom() is safe as a CSPRNG source, but misuse occurs when its output is improperly transformed or mixed with weak PRNGs. Tool flags usage to prompt review.",
                "recommendation": "Use secrets API or os.urandom() directly for keys; do not pass os.urandom() into non-crypto PRNGs. Ensure output is used in cryptographically-appropriate ways (e.g., key material, token bytes)."
            }

    # --- Case 4: Direct imported weak random function ---
    if isinstance(func, ast.Name):
        snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
        if len(snippet) > 400:
            snippet = snippet[:400] + "..."
        if func.id == "uuid4":
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A02 Cryptographic Failures",
                "rule": "216",
                "vulnerability": "Direct use of uuid4() treated as weak for some contexts",
                "severity": "MEDIUM",
                "description": "uuid.uuid4() provides randomness but may not be suitable as a secret token (predictability depending on environment/implementation). Your rule set flags it as weak for high-security tokens.",
                "recommendation": "Prefer secrets.token_urlsafe() or secrets.token_bytes() for secrets; uuid4() is fine for identifiers but not for auth tokens."
            }
        if func.id in {"random", "randint", "randrange", "choice"}:
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A02 Cryptographic Failures",
                "rule": "207",
                "vulnerability": "Use of weak PRNG functions for security-sensitive values",
                "severity": "MEDIUM",
                "description": "Calls to random.random()/randint()/choice(), numpy.random, uuid4() (per your rule set), or other non-cryptographic RNGs are unsuitable for keys, tokens or secrets.",
                "recommendation": "Use Python's secrets module for token/key generation, or os.urandom()/secrets for bytes. Reserve random/numpy.random for non-security uses like simulations."
            }

    return None

WEAK_HASH_FUNCS = {"md5", "sha1", "md4", "sha224", "sha256", "sha512"}  # weak for passwords
STRONG_HASH_FUNCS = {"pbkdf2_hmac", "scrypt", "bcrypt", "argon2"}
HMAC_MODULES = {"hmac"}

def check_weak_hash(node):
    if not isinstance(node, ast.Call):
        return None
    snippet = ""
    try:
        snippet = safe_unparse(node).strip()
    except Exception:
        snippet = ""
    snippet = (snippet or "")[:400]

    # --- Case 1: hashlib.md5(...), hashlib.sha1(...), etc. ---
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            func = node.func.attr

            # weak hash from hashlib.*
            if module == "hashlib" and func in WEAK_HASH_FUNCS:
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A02 Cryptographic Failures",
                    "rule": "211",
                    "vulnerability": "Weak hash algorithm usage (MD5, SHA1) for passwords/integrity",
                    "severity": "HIGH",
                    "description": "Using fast or broken hashes (MD5, SHA-1) for password storage or integrity allows trivial brute-force and collision attacks.",
                    "recommendation": "Use modern password KDFs: bcrypt, scrypt, argon2, or PBKDF2-HMAC with a strong iteration count and per-password salt. For integrity/authenticated hashing use HMAC with a strong hash (e.g., SHA-256) or an AEAD algorithm."
                }

            # e.g. hmac.new(..., digestmod=hashlib.md5)
            if module in HMAC_MODULES and func == "new":
                for kw in node.keywords:
                    if kw.arg == "digestmod" and isinstance(kw.value, ast.Attribute):
                        if isinstance(kw.value.value, ast.Name) and kw.value.attr in WEAK_HASH_FUNCS:
                            return {
                                "line": node.lineno,
                                "function": node.name,
                                "category": "A02 Cryptographic Failures",
                                "rule": "212",
                                "vulnerability": "Weak digest used inside HMAC (hmac.new(..., digestmod=hashlib.md5))",
                                "severity": "HIGH",
                                "description": "HMAC with a weak digest reduces security guarantees; MD5/SHA1 are not suitable for modern integrity/authentication.",
                                "recommendation": "Use hmac.new(..., digestmod=hashlib.sha256) or stronger; prefer established constructions and key management."
                            }

            # --- Case 2: hashlib.new("md5") ---
            if func == "new" and node.args and isinstance(node.args[0], ast.Constant):
                if node.args[0].value in WEAK_HASH_FUNCS:
                    return {
                        "line": node.lineno,
                        "function": snippet,
                        "category": "A02 Cryptographic Failures",
                        "rule": "213",
                        "vulnerability": "Using hashlib.new(\"md5\") or hashlib.md5() via hashlib",
                        "severity": "HIGH",
                        "description": "Explicit selection of weak algorithms is insecure for secrets or signatures.",
                        "recommendation": "Switch to modern algorithms or use crypto libraries that enforce secure choices (and avoid rolling your own)."
                    }

    # --- Case 3: Direct usage of base64 for “hashing” passwords ---
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name) and node.func.value.id == "base64":
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A02 Cryptographic Failures",
                "rule": "214",
                "vulnerability": "Using base64 encoding as a “hash” for passwords",
                "severity": "HIGH",
                "description": "Base64 encodes data, it is not a cryptographic hash and offers no irreversibility against attackers.",
                "recommendation": "Use proper password hashing / KDFs (bcrypt, scrypt, argon2). Never store plain/base64-encoded passwords."
            }

    # --- Case 4: Custom hash via sum(), ord(), or XOR in comprehension ---
    if isinstance(node.func, ast.Name):
        if node.func.id in {"sum", "ord"} and any(isinstance(arg, (ast.ListComp, ast.GeneratorExp)) for arg in node.args):
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A02 Cryptographic Failures",
                "rule": "215",
                "vulnerability": "Custom ad-hoc hashing with sum()/ord() or simple transforms",
                "severity": "MEDIUM",
                "description": "Homemade hashing or checks (summing bytes, ord-based transforms) are non-cryptographic and trivially reversible or forgeable.",
                "recommendation": "Use vetted cryptographic primitives and KDFs; avoid custom constructions entirely."
            }

    return None

RULES2 = [
    check_hardcoded_secret,
    check_db_url,
    check_dict_hardcoded_credentials,
    check_function_defaults,
    check_class_secrets,
    check_weak_randomness,
    check_weak_hash,
]

'''
HIGH-CRITICAL
Weak hash algorithm (hashlib.md5, hashlib.sha1)
Hardcoded cryptographic keys and secret 
Insecure pseudo-random generators for crypto (random.random() for keys)
Insecure cipher mode (modes.ECB)
Missing or disabling SSL/TLS verification (requests.get(..., verify=False))
'''