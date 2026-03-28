import ast
        
# === A05 Security Misconfiguration ===

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
        
def check_exception_handler(node, analyzer=None):
    """
    Unified rule to detect poor exception handling patterns:
      - bare except
      - broad Exception/BaseException
      - empty/pass-only body
      - returning None (swallowing error)
      - print-only handler
      - security bypass (assign True)
    Ensures no duplicate alerts for the same except block.
    """
    if not isinstance(node, ast.ExceptHandler):
        return None

    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 400:
        snippet = snippet[:400] + "..."

    # Determine exception type name (if any)
    exc_name = None
    if node.type and isinstance(node.type, ast.Name):
        exc_name = node.type.id

    # --- Priority 1: bare except
    if node.type is None:
        # if body trivial (pass, continue, return None)
        if all(
            isinstance(stmt, (ast.Pass, ast.Continue)) or
            (isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant) and stmt.value.value is None)
            for stmt in node.body
        ):
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A05 Security Misconfiguration",
                "rule": "502",
                "vulnerability": "Bare except: with trivial handling (pass/return None)",
                "severity": "HIGH",
                "description": "A catch-all combined with a trivial handler (just 'pass' or 'return None') silences errors and makes debugging and auditing impossible — can lead to silent data corruption or security bypass.",
                "recommendation": "Remove trivial handlers. At minimum log the exception and include context; re-raise when appropriate. Add unit tests that assert errors bubble up in failure cases."
            }
        return {
            "line": node.lineno,
            "function": snippet,
            "category": "A05 Security Misconfiguration",
            "rule": "501",
            "vulnerability": "Bare except: (catch-all)",
            "severity": "HIGH",
            "description": "A bare 'except:' catches everything (including KeyboardInterrupt, SystemExit, interrupts, and unexpected errors), making it easy to silently swallow critical failures or hide security problems.",
            "recommendation": "Catch specific exceptions (e.g., except ValueError:). If you truly need a fallback, re-raise or log the original exception and limit the scope of the try block."
        }

    # --- Priority 2: broad exception types (Exception/BaseException)
    if exc_name in ("Exception", "BaseException"):
        sev = "HIGH" if exc_name == "BaseException" else "MEDIUM"

        # if only trivial body (pass, continue, return None)
        if all(
            isinstance(stmt, (ast.Pass, ast.Continue)) or
            (isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant) and stmt.value.value is None)
            for stmt in node.body
        ):
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A05 Security Misconfiguration",
                "rule": "504",
                "vulnerability": "Trivial handler for broad exception (pass / return None)",
                "severity": "HIGH",
                "description": "Catching 'Exception'/'BaseException' then doing nothing or returning 'None' effectively swallows all errors and hides root causes — high operational and security risk.",
                "recommendation": "Don’t swallow broad exceptions. Log full traceback and either re-raise or return a well-documented error object/response. Use structured error types where callers can handle them."
            }
        return {
            "line": node.lineno,
            "function": snippet,
            "category": "A05 Security Misconfiguration",
            "rule": "503",
            "vulnerability": "Catching broad exception types ('Exception', 'BaseException')",
            "severity": sev,
            "description": "Catching 'Exception' hides many unexpected runtime errors; catching 'BaseException' is worse because it includes system-level exceptions. Both mask failures and can prevent cleanup or correct error handling.",
            "recommendation": "Replace with the narrowest exception(s) required. For library code, prefer letting exceptions propagate to callers. If you must catch Exception, at least log and re-raise or wrap with additional context."
        }

    # --- Priority 3: Specific exception, but trivial handler
    # a) return None
    for stmt in node.body:
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant) and stmt.value.value is None:
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A05 Security Misconfiguration",
                "rule": "505",
                "vulnerability": "Returning None in an except (silent swallow)",
                "severity": "MEDIUM",
                "description": "Returning 'None' from an exception handler hides the cause and makes downstream code treat failure results as valid input, which can trigger subtle bugs and security issues.",
                "recommendation": "Return explicit error values/types or raise a new exception with context. If returning 'None' is intended, document it and ensure callers check for it."
            }

        # b) print-only handler
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            if getattr(stmt.value.func, "id", None) == "print":
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A05 Security Misconfiguration",
                    "rule": "506",
                    "vulnerability": "Print-only handlers",
                    "severity": "LOW",
                    "description": "Calling 'print()' in an exception handler is insufficient for production visibility; it doesn’t integrate with logging, monitoring, or structured alerting and can be missed in many runtimes.",
                    "recommendation": "Replace 'print()' with structured logging (e.g., logger.error(..., exc_info=True)). Include context and, where appropriate, correlation IDs."
                }

        # c) security bypass: valid = True
        if isinstance(stmt, ast.Assign):
            if isinstance(stmt.value, ast.Constant) and stmt.value.value is True:
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A05 Security Misconfiguration",
                    "rule": "507",
                    "vulnerability": "Security-bypass pattern (setting flags like valid = True in except)",
                    "severity": "HIGH",
                    "description": "Setting boolean \"success\" flags inside exception handlers (e.g., valid = True) can incorrectly mark operations as successful after an error, bypassing security checks or validation flows.",
                    "recommendation": "Never set success flags based on exceptions. Use explicit control flow: set flags only upon successful completion, and ensure exception paths set error states or raise. Add assertions/unit tests that verify flags are only set on success."
                }
 
    return None     # Nothing matched

# --- Other rules that analyze non-except nodes stay separate ---

def check_reraise_new_exception(node, analyzer=None):
    if not isinstance(node, ast.Raise):
        return None
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."

    if hasattr(analyzer, "current_except") and analyzer.current_except:
        if isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name):
            return {
                "line": node.lineno,
                "function": snippet,
                "category": "A05 Security Misconfiguration",
                "rule": "508",
                "vulnerability": "Re-raising a new exception (loses original traceback)",
                "severity": "LOW",
                "description": "Raising a new exception inside an 'except' without preserving the original (raise NewError from e) drops the original traceback, making debugging harder and obscuring root cause.",
                "recommendation": "Chain exceptions with 'raise NewError(...) from e' to preserve context, or re-raise the original (raise) if appropriate. Include additional context rather than discarding it."
            }

    return None

def check_busy_retry_loop(node, analyzer=None):
    if not isinstance(node, ast.While):
        return None
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."

    if isinstance(node.test, ast.Constant) and node.test.value is True:
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.ExceptHandler) and any(isinstance(b, ast.Continue) for b in stmt.body):
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A05 Security Misconfiguration",
                    "rule": "509",
                    "vulnerability": "Busy retry loop with no delay/logging (CPU spin or silent retry)",
                    "severity": "HIGH",
                    "description": "An infinite 'while True:' retry loop that continues immediately after exceptions (especially with continue) can cause CPU spin, resource exhaustion, or repeated silent failures.",
                    "recommendation": "Add exponential backoff/retry limits, logging for each retry, and an eventual fail path. Use 'time.sleep()' or backoff libraries, and cap retries."
                }

    return None

def check_import_with_pass(node, analyzer=None):
    if not isinstance(node, ast.Try):
        return None
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."
    for handler in node.handlers:
        if isinstance(handler.type, ast.Name) and handler.type.id == "ImportError":
            if all(isinstance(b, ast.Pass) for b in handler.body):
                return {
                    "line": node.lineno,
                    "function": snippet,
                    "category": "A05 Security Misconfiguration",
                    "rule": "510",
                    "vulnerability": "Silently ignoring ImportError with pass",
                    "severity": "HIGH",
                    "description": "Swallowing 'ImportError' (i.e., ignoring a missing module) can disable critical functionality silently or lead to insecure fallback behaviors. It is especially dangerous when optional imports control security features.",
                    "recommendation": "Fail fast with a clear error or degrade gracefully with explicit logging and documented behavior. If a dependency is optional, check availability and provide a safe fallback, plus tests for both paths."
                }
    return None

def check_asyncio_ignore_exception(node, analyzer=None):
    if not isinstance(node, ast.Call):
        return None
    snippet = safe_unparse(node) or (safe_unparse(node) if node else "")
    if len(snippet) > 500:
        snippet = snippet[:500] + "..."
    # detect task.add_done_callback(lambda t: t.exception())
    if isinstance(node.func, ast.Attribute):
        if node.func.attr == "add_done_callback" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Lambda):
                if isinstance(arg.body, ast.Call) and isinstance(arg.body.func, ast.Attribute):
                    if arg.body.func.attr == "exception":
                        return {
                            "line": node.lineno,
                            "function": snippet,
                            "category": "A05 Security Misconfiguration",
                            "rule": "511",
                            "vulnerability": "Async task exceptions ignored via add_done_callback(lambda t: t.exception())",
                            "severity": "MEDIUM",
                            "description": "Calling 'Task.exception()' in a callback and not handling or logging the returned exception discards errors from background tasks, making asynchronous failures invisible.",
                            "recommendation": "In the callback, inspect 't.exception()' and log/handle it. Consider await-ing tasks where possible or use 'asyncio.create_task(...); task.add_done_callback(handle_task_result)' where 'handle_task_result' logs exceptions and triggers remediation."
                        }
    return None

RULES5 = [
    check_exception_handler,
    check_reraise_new_exception,
    check_busy_retry_loop,
    check_import_with_pass,
    check_asyncio_ignore_exception,
]

'''
MEDIUM-HIGH
Debug mode enabled (app.run(debug=True))
Insecure HTTP settings (verify=False or allow_redirects=True without validation)
Poor exception handling (except: pass, except Exception: return None, no logging)
Insecure file permissions (os.chmod(file, 0o777))
'''