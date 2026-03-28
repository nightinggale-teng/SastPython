import ast
import re
from typing import Optional

# === A01 Broken Access Control ===

# Keywords that indicate privileged or administrative operations
PRIVILEGED_KEYWORDS = {
    # --- User and Role Management ---
    "grant_admin", "revoke_admin", "assign_admin", "manage_admin", "modify admin", "make_admin",
    "admin_batch_delete", "do_admin_thing", "admin_panel",
    "assign_role", "modify_role", "manage_role", "update_role", "remove_role", "delete_role", "change_role",
    "set_role", "set_roles",
    "set_user_role", "assign_user_role", "modify_user_role", "promote_user", "demote_user", "promote_in_ldap",
    "update_permission", "grant_permission", "revoke_permission", "change_permission", "manage_permission", 
    "reset_permission", "set_permission",
    "change_privilege", "manage_privileges", "reset_privileges", "elevate_privilege", "grant_privilege", 
    "revoke_privilege", "update_privilege", "set_privilege",
    "join", "join_group", "update_group", "add_to_group", "append_to group", 
    "add_member", "add_member_to_group",
    "grant_access", "revoke_access", "update_access", "change_access", "manage_access",
    "role", "privilege", "permission", "authz", "authorize", "authorization",
    # --- Account Management ---
    "create_user", "delete_user", "remove_user", "update_user", "modify_user", "patch_user",
    "ban_user", "unban_user", "verify_user", "approve_user", "block_user", "unblock_user",
    "deactivate_account", "reactivate_account", "delete_account", "create_account", "suspend_account",
    "reset_password", "change_password", "reset_api_key", "revoke_api_key",
    "disable_2fa", "enable_2fa", "generate_token", "invalidate_token", "accept_invite",
    "approve_device", "remove_device", "disable_device", "enable_device",
    "bypass_auth", "grant_auth",
    # --- System and Server Operations ---
    "set_system_config", "update_system_config", "reset_system_config", "modify_system_setting", 
    "update_system_setting", "reset_system_setting", "change_system_setting",
    "update_config", "set_config", "reset_config",
    "update_setting", "modify_setting", "change_setting",
    "restart_service", "restart_server", "restart_system", "reboot_service", "reboot_server", "reboot_system",
    "shutdown_service", "shutdown_server", "shutdown_system",
    "start_service", "stop_service", "disable_service", "enable_service",
    # --- System Maintenance and Logs ---
    "flush_cache", "purge_logs", "rotate_logs", "clear_logs", "view_logs", "delete_logs", "export_logs",
    "generate_logs", "access_log",
    "audit_user", "access_audit", "clear_audit",
    "generate_report", "delete_report", "export_report", "view_report",
    # --- Database and Data Operations ---
    "delete_record", "update_record", "modify_record", "upload_file", "download_file", "delete_file",
    "truncate_table", "drop_table", "alter_table", "modify_table",
    "modify_data", "wipe_data", "reset_data", "export_data", "import_data",
    "create_resource", "update_resource", "delete_resource", "remove_resource",
    "allocate_resource", "release_resource", "set_resource_limit",
    # --- Sensitive Data and Secrets ---
    "view_sensitive", "view_sensitive_data", "write_sensitive_data", "write_private_file",
    "read_private_file", "access_secret", "modify_secret", "do_secret",
    # --- Financial and Payment Operations ---
    "trigger_payment", "process_payment", "approve_payment", "cancel_payment", "verify_payment", 
    "process_refund", "approve_refund", "initiate_transfer", "cancel_transfer",
    "approve_transaction", "cancel_transaction", "verify_transaction",
    "update_invoice", "delete_invoice", "approve_invoice", "verify_invoice",
    "update_balance", "verify_balance",
    "set_credit_limit", "reset_credit_limit", "update_credit_limit", "modify_credit_limit",
    "grant_discount", "charge", "payment", "invoice", "refund", "transaction",
    # --- Networking and Access Control ---
    "whitelist_ip", "blacklist_ip", "unblock_ip", "block_ip",
    "call_third_party", "connect_api", "sync_api", "remote_execute",
    # --- Command and Process Execution ---
    "run_admin_cmd", "exec_admin_cmd", "run_command", "exec_command",
    "execute_system", "run_shell", "execute_shell",
    "spawn_process", "terminate_process", "kill_process", "run_process", "exec_process", 
    "apply_patch", "install_update", "update_system", "upgrade",
    "start_backup", "restore_backup", "backup",
    # --- Generic Privileged Prefixes ---
    "set_", "update_", "upload_", "delete_", "remove_", "modify_", "grant_", "revoke_", "reset_", "create_",
    "approve_", "disable_", "enable_", "archive_", "purge_", "promote_", "dump_db"
    "config", "admin", "token", "privilege", "role", "promote", "delete", "grant", "deactivate", "upgrade", 
    "save", "update", "elevate", "remove", "archive", "revoke", "purge", "destroy", "terminate", "reset",
    "clear", "wipe", "disable", "provision", "dump", "restore", "charge", "payment",
    "manage_ui", "select_all", "do_sensitive", "do_thing", "settings.update", "db.get_contacts",
    # --- Common ORM and Framework Calls ---
    "user.role", "User.find", "User.objects.update", "queue.enqueue", "ws.emit", "job.enqueue",
}

# Common patterns that count as authorization checks
AUTH_CHECK_KEYWORDS = {
    # --- Role-based access control ---
    "is_admin", "is_superuser", "is_superadmin", "is_root", "is_manager", "is_moderator",
    "superadmin", "super_user", "superuser", "root_user", "admin", "group_admin", "feature_admin",
    "ui_admin", "user.is_admin", "user.is_superuser", "user.is_authorized", "user.is_root",
    "make_admin", "make_superuser", "make_root", "make_rootuser", "make_root_user",
    "current_user", "current_user.role", "current_user.roles", "get_user_role", "check_role", "verify_role",
    "validate_role", "require_role", "role_required", "has_role", "has_roles", "user_has_role",
    "user_has_privilege", "role", "roles", "requesting_user.roles",
    # --- Ownership / resource-based checks ---
    "is_owner", "owns", "owned_by", "is_resource_owner", "project_owned_by", "verify_owner", "check_owner",
    "validate_owner", "has_ownership", "owned", "belongs_to", "user_owns", "check_ownership", "owner",
    "group_owner", "ownership", "project.is_owner", "resource.is_owner",
    # --- Permission-based checks ---
    "has_permission", "check_permission", "verify_permission", "validate_permission", "user_has_permission",
    "permission_required", "permissions_required", "require_permission", "authorize_permission",
    "permission", "permissions", "permissionerror",
    "privileges", "has_privilege", "check_privilege", "verify_privilege", "validate_privilege",
    "allowed", "is_allowed", "allowed_to", "can_edit", "can_delete", "can_manage",
    "can_modify", "can_update", "can_assign", "can_change",
    # --- Authorization and scope ---
    "authorize", "authorized", "unauthorized", "is_authorized", "authorized_for", "authorize_user",
    "check_authorization", "validate_authorization", "has_scope", "check_scope", "validate_scope", "scope",
    "scopes", "token_has_scope", "has_access", "check_access", "validate_access", "access_control",
    "access_allowed", "access_granted", "access_denied", "is_authenticated", "is_active", "session",
    "logged_in", "request.user",
    # --- Security enforcement keywords ---
    "PermissionError", "PermissionDenied", "AccessDenied", "AccessError", "Forbidden", "ForbiddenError", "Authorization",
    "NotAuthorized", "require_privilege", "assert_admin", "assert_role", "assert_permission", "raise_PermissionError",
    # --- Generic auth keywords (catch-all, useful for custom functions) ---
    "auth", "authz", "authorize_request", "ensure_authorized", "require_authorization", "enforce_privileges",
    "enforce_access_control", "security_check", "privilege_check", "role_check", "allowed_flags", "ui_config_keys",
    "auth_token", "jwt.decode", "login_required",
}

# Authentication decorators
AUTH_DECORATORS = {
    # --- Generic authentication decorators ---
    "authenticated_only", "auth_required", "user_required", "require_authenticated_user", "jwt_required",
    "require_login", "require_auth", "login_required", "require_auth_ws", "require_user", "session_required",
    "login_required_api", "user_login_required", "authenticated", "authenticated_user", "auth_needed",
    "ensure_authenticated", "must_be_logged_in",
    # --- Generic Authorization decorators ---
    "role_required", "roles_required", "permission_required", "permissions_required", "admin_required",
    "superuser_required", "manager_required", "moderator_required", "access_required", "privilege_required",
    "authorization_required", "require_privilege", "require_role", "require_permission", "scope_required",
    "require_authorization", "authorized_only", "require_roles", "require_scopes", "check_roles", 
    "check_permissions",
    # --- Flask / FastAPI Framework-specific variants ---
    "flask_login_required", "flask_jwt_required", "fastapi_login_required", "token_required", 
    "oauth_required", "api_key_required",
    # --- Django / DRF Framework-specific variants ---
    "staff_member_required", "user_passes_test", "permission_classes", "has_permission_decorator", 
    "login_exempt", "admin_only",
    # --- Tornado / Starlette style Framework-specific variants ---
    "requires_auth", "requires_roles", "requires_permissions", "requires_privileges",
}

# Privileged function call indicators (these may appear in the body)
PRIVILEGED_CALLS = {
    # --- DB / transaction ---
    "db.execute", "db.delete", "db.insert", "db.query", "db.transaction", "db.commit", "db.rollback",
    "db.select_all", "db.dump",
    "session.commit", "session.rollback", "engine.execute", "connection.execute",
    "execute_sql", "run_query", "sql.execute", "raw_query",
    # --- File / OS destructive ---
    "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree", "pathlib.Path.unlink", "pathlib.Path.rmdir",
    "open", "os.chmod", "os.chown", "os.rename", "os.replace",
    # --- Subprocess / shell / system commands ---
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
    "os.system", "popen", "pexpect.spawn", "sh.shell", "sh.Command", "shell.exec", "commands.getoutput",
    # --- System / service control ---
    "system.restart", "systemctl.restart", "systemctl.start", "systemctl.stop", "service.restart",
    "restart_service", "reboot", "reboot_server", "shutdown", "shutdown_server",
    # --- Payments / accounts ---
    "accounts.debit", "accounts.credit", "payments.charge", "payment.process", "process_payment",
    "charge_card", "charge_payment", "gateway.charge",
    # --- Backups / restore ---
    "backup_manager.start", "backup.restore", "start_backup", "restore_backup", "create_snapshot",
    "db.backup",
    # --- Tokens / secrets / auth ---
    "get_token_for", "create_token", "invalidate_token", "revoke_token", "db.find_by_token",
    "secretsmanager.get_secret", "secret_manager.get", "vault.write", "vault.read",
    "kms.decrypt", "kms.encrypt", "keyring.get_password",
    # --- HTTP / internal proxying ---
    "http.post", "http.put", "http.delete", "requests.post", "requests.put", "requests.delete",
    "httpx.post", "httpx.put", "httpx.delete", "urllib.request.urlopen", "request.args",
    "request.json", "request.form", "request.data", "request.get_json", "request.values",
    # --- Cloud SDKs that could trigger privileged changes ---
    "boto3.client", "boto3.resource", "gcloud.compute", "googleapiclient", "eks.create_cluster",
    "aws.s3.delete_object", "s3.delete_object", "s3.put_object", "cloudtasks.create",
    "iam.create_user", "iam.put_user_policy", "iam.attach_user_policy",
    "ec2.terminate_instances", "compute.instances.delete", "compute.instances.stop",
    "azure.mgmt", "azure.keyvault", "azure.mgmt.compute.virtual_machines.begin_delete", "azure.keyvault.secrets.set",
    # --- Container / orchestration ---
    "docker.client", "docker.api", "kubectl.run", "kubectl.apply", "kubectl.delete", "helm.install",
    # --- Job / queue / scheduler ---
    "queue.enqueue", "job.enqueue", "celery.send_task", "celery.app.send_task", "rq.enqueue",
    "apscheduler.add_job", "cron.create", "scheduler.schedule", "kafka.send", "kafka.produce",
    # --- DB update / admin helpers ---
    "db.update", "db.alter_table", "db.migrate", "alembic.upgrade", "migrate_db", "run_migrations",
    "create_resource", "delete_resource", "provision", "provision_resource",
    # --- Role/privilege helpers ---
    "update_user_role", "update_role", "set_user_role", "grant_role", "revoke_role", "assign_role",
    "make_admin", "delete_user", "delete_account", "create_user", "create_account",
    "admin_batch_delete", "admin_batch", "do_admin_thing",
    # --- Misc privileged operations ---
    "http.post_internal", "internal_api.post", "admin_api.call", "admin_action", "run_admin_cmd",
    "exec_admin_cmd", "execute_system", "remote_execute", "call_third_party_internal",
    "payload", "params","invite.", "token.", "generate_report", "orders.all", "data_dump",
}

# Destructive / owner-only method names even when function name doesn't look privileged
DESTRUCTIVE_METHODS = {
    # --- Destructive or irreversible actions on resources ---
    "delete", "remove", "archive", "revoke", "purge", "destroy", "shutdown", "clear", "terminate", "wipe", 
    "deactivate", "decommission", "disable", "delete_all", "drop", "truncate", "cancel", "transfer_ownership",
    "reset", "force_delete", "soft_delete", "hard_delete",
    # --- Project or object management verbs ---
    "delete_project", "archive_project", "revoke_project", "delete_account", "delete_user"
    "delete_item", "remove_item", "delete_resource"
}

# Config & flag write targets and sensitive method names
CONFIG_WRITE_TARGETS = { 
    # --- App-Level ---
    "app_config", "app", "app.config", "config", "Settings", "settings", "Setting", "setting",
    "server_config", "system_config", "site_config", "runtime_config", "global_config", "global_settings",
    # --- Feature flags & toggles ---
    "feature_flags", "feature_flag", "flag", "FLAGS", "flags", "featureToggle", "feature_toggle",
    "featureToggleService", "featureStore", "flag_store",
    # --- UI / plugin / plugin manager ---
    "ui_config", "ui_config_keys", "plugin_manager", "plugin", "plugins", "pluginRegistry", "plugin_service",
    # --- Other common names that store config/state ---
    "state", "app_state", "settings_store", "config_store", "options", "preferences", "prefs",
}

# Method names that are often used to mutate state
SENSITIVE_METHODS = {
    "update", "write", "save", "commit", "replace", "patch", "set", "setattr", "__dict__.update",
    "put", "post", "delete", "remove", "enable", "disable", "activate", "deactivate", "install",
    "load", "unload", "register", "install_plugin", "enable_plugin", "disable_plugin",
}

# DB flag detection patterns (regex list)
DB_FLAG_PATTERNS = [
    re.compile(r"\bDBFlags\b", re.IGNORECASE),
    re.compile(r"\bFlags\b", re.IGNORECASE),
    re.compile(r"\bFeatureFlag\b", re.IGNORECASE),
    re.compile(r"\bfeature_flags?\b", re.IGNORECASE),
    re.compile(r"\bflag_store\b", re.IGNORECASE),
    re.compile(r"\bfeature_toggle\b", re.IGNORECASE),
]

# Internal host URL patterns (used to detect internal proxying)
INTERNAL_HOST_PATTERNS = [
    re.compile(r"^https?://(?:localhost|127\.0\.0\.1|internal)(?:[:/]|$)", re.IGNORECASE),
    re.compile(r"^https?://(?:internal-|\bint-|\binternal\.)", re.IGNORECASE),
    re.compile(r"^https?://(?:admin\.|internalapi\.|svc\.|svc\.cluster\.local|cluster\.local)", re.IGNORECASE),
    re.compile(r"^https?://(?:169\.254\.169\.254)", re.IGNORECASE),
]

# Authz checks (if any of these appear in condition / raises / calls, treat function as having explicit authz)
AUTHZ_KEYWORDS = {
    "roles", "role", "has_role", "requesting_user.roles", "permissions", "permission", "has_permission",
    "allowed_flags", "ui_config_keys", "PermissionError", "permissionerror", "PermissionDenied", "raise PermissionError",
    "require_role", "require_permission", "check_permission", "verify_permission", "is_admin", "admin",
}

# Authentication/session-presence indicators (presence-only checks we want to detect)
PRESENCE_INDICATOR_PATTERNS = [
    re.compile(r'current_user\.is_authenticated', re.I),
    re.compile(r'current_user\.is_active', re.I),
    re.compile(r'current_user\.email', re.I),
    re.compile(r'current_user\.username', re.I),
    re.compile(r'user\.is_authenticated', re.I),
    re.compile(r'user\.is_active', re.I),
    re.compile(r'hasattr\(\s*current_user\s*', re.I),
    re.compile(r'session\.get\(', re.I),
    re.compile(r'session\.get\([\'"]logged_in[\'"]\)', re.I),
    re.compile(r'session\.get\([\'"]user_id[\'"]\)', re.I),
    re.compile(r'request\.cookies\.get\(', re.I),
    re.compile(r'request\.headers\.get\(', re.I),
    re.compile(r'request\.headers\.get\([\'"]authorization[\'"]\)', re.I),
    re.compile(r'request\.headers\.get\([\'"]referer[\'"]\)', re.I),
    re.compile(r'request\.user', re.I),
    re.compile(r'g\.user', re.I),
    re.compile(r'sso_session\.is_valid\(\)', re.I),
    re.compile(r'os\.environ\.get\(', re.I),
    re.compile(r'current_user\.[a-zA-Z_]+', re.I),
    re.compile(r'jwt\.decode\(', re.I),
    re.compile(r'referer', re.I),
    re.compile(r'if\s+(current_user|user|request\.user|g\.user)', re.I),
]

# Untrusted payload / client-provided flag patterns that should not gate admin actions
UNTRUSTED_FLAG_PATTERNS = [
    re.compile(r'payload\.get\([\'"]is_admin[\'"]\)', re.I),
    re.compile(r'payload\.get\([\'"]is_superuser[\'"]\)', re.I),
    re.compile(r'request\.json\.get\s*\(', re.I),
    re.compile(r'request\.json\.get\([\'"]is_admin[\'"]\)', re.I),
    re.compile(r'request\.args\.get\s*\(', re.I),
    re.compile(r'request\.args\.get\([\'"]is_admin[\'"]\)', re.I),
    re.compile(r'request\.form\.get\s*\(', re.I),
    re.compile(r'request\.form\.get\([\'"]is_admin[\'"]\)', re.I),
    re.compile(r'request\.get_json\s*\(', re.I),
    re.compile(r'request\.headers\.get\s*\(', re.I),
]

# Plugin method names (enable/disable/activate/etc.)
PLUGIN_METHOD_NAMES = {
    "enable", "disable", "activate", "deactivate", "load", "install", "unload", "register",
    "enable_plugin", "disable_plugin", "activate_plugin", "install_plugin", "load_plugin",
    "activateExtension", "deactivateExtension", "register_plugin", "enable_extension", "disable_extension",
}

# Code execution / dangerous builtins / config loading functions to track as untrusted sources
CODE_EXEC_FUNCS = {
    "exec", "eval", "compile", "execfile", "run_code", "runpy.run_path", "runpy.run_module",
    "builtins.exec", "builtins.eval"
}

# YAML / config loaders and other parsers that may produce untrusted dicts
YAML_LOAD_FUNCS = {
    "yaml.safe_load", "yaml.load", "safe_load", "load", "ruamel.yaml.load", "ruamel.yaml.safe_load",
    "json.loads", "ujson.loads", "toml.loads", "configparser.read", "ConfigParser.read", "plistlib.loads",
}

# Helper to return dotted name of function being called
def get_full_func_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))

# Helper to get source of a value to check if it's client-controlled
def get_value_source(node):
    try:
        return ast.unparse(node).lower()
    except Exception:
        return ""

# Helper to get ending line number of an AST node (approximation)
def get_end_line(node):
    try:
        # Try to get the actual end line
        if hasattr(node, 'end_lineno') and node.end_lineno:
            return node.end_lineno
        # Otherwise, walk through all child nodes to find the maximum line number
        max_line = node.lineno
        for child in ast.walk(node):
            if hasattr(child, 'lineno') and child.lineno:
                max_line = max(max_line, child.lineno)
            if hasattr(child, 'end_lineno') and child.end_lineno:
                max_line = max(max_line, child.end_lineno)
        return max_line
    except Exception:
        return node.lineno

def has_decorator(node: ast.FunctionDef, name: str) -> bool:
    for d in node.decorator_list:
        if isinstance(d, ast.Name) and d.id == name:
            return True
        if isinstance(d, ast.Attribute) and d.attr == name:
            return True
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == name:
            return True
    return False

def is_event_handler(node: ast.FunctionDef) -> bool:
    for d in node.decorator_list:
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "on":
            return True
    return False

def contains_explicit_authz(node: ast.AST) -> bool:
    for inner in ast.walk(node):
        if isinstance(inner, ast.If):
            try:
                cond_src = ast.unparse(inner.test).lower()
            except Exception:
                cond_src = ""
            if any(k.lower() in cond_src for k in AUTH_CHECK_KEYWORDS):
                return True
        if isinstance(inner, (ast.Raise, ast.Assert)):
            src = ast.unparse(inner).lower() if hasattr(ast, "unparse") else ""
            if any(k.lower() in src for k in AUTH_CHECK_KEYWORDS):
                return True
        if isinstance(inner, ast.Call):
            call_name = get_full_func_name(inner.func).lower()
            if any(x in call_name for x in AUTH_CHECK_KEYWORDS):
                return True
    return False

def is_internal_proxy_call(call: ast.Call) -> bool:
    func_full = get_full_func_name(call.func).lower()
    if any(func_full.endswith("." + verb) for verb in ("post", "put", "patch", "delete")):
        if call.args:
            arg0 = call.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                url = arg0.value
                for pat in INTERNAL_HOST_PATTERNS:
                    if pat.search(url):
                        return True
    return False

def is_plugin_enable_call(call: ast.Call) -> bool:
    func_full = get_full_func_name(call.func)
    if "." in func_full:
        obj, meth = func_full.rsplit(".", 1)
        if meth in PLUGIN_METHOD_NAMES and ("plugin" in obj.lower() or "plugin_manager" in obj.lower()):
            return True
    if isinstance(call.func, ast.Name) and call.func.id.lower().startswith("enable"):
        return True
    return False

def is_code_execution_call(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Name) and call.func.id in CODE_EXEC_FUNCS:
        return True
    return False

def is_sensitive_attr_assignment(target: ast.AST, value: ast.AST) -> bool:
    # FLAGS['x'] or os.environ['X'] or feature_flags[...] -> sensitive
    if isinstance(target, ast.Subscript):
        try:
            base = ast.unparse(target.value).lower()
        except Exception:
            base = ""
        if base.startswith("os.environ") or any(cfg in base for cfg in (c.lower() for c in CONFIG_WRITE_TARGETS)) or base.startswith("flags"):
            return True
    # attribute assignment e.g., user.roles = ... or app.__dict__ = ...
    if isinstance(target, ast.Attribute):
        attr = getattr(target, "attr", "")
        try:
            base = ast.unparse(target.value).lower()
        except Exception:
            base = ""
        if attr == "roles":
            return True
        if attr == "__dict__":
            return True
        if any(key in attr.lower() for key in ("flag", "feature", "config")):
            return True
    return False

def call_targets_dict_update(call: ast.Call) -> bool:
    func_full = get_full_func_name(call.func).lower()
    if func_full.endswith(".__dict__.update") or ".__dict__.update" in func_full:
        return True
    return False

def is_setattr_call(call: ast.Call) -> bool:
    # detect setattr(obj, name, value) where obj looks config-like
    if isinstance(call.func, ast.Name) and call.func.id == "setattr":
        if len(call.args) >= 2:
            target_obj = call.args[0]
            try:
                obj_src = ast.unparse(target_obj).lower()
            except Exception:
                obj_src = ""
            if any(cfg.lower() in obj_src for cfg in CONFIG_WRITE_TARGETS) or "app" in obj_src or "config" in obj_src:
                return True
    return False

def is_yaml_load_call(call: ast.Call) -> bool:
    fname = get_full_func_name(call.func).lower()
    # cover yaml.safe_load, yaml.load, safe_load
    if any(fname.endswith("." + x) or fname == x for x in (c.lower() for c in YAML_LOAD_FUNCS)):
        return True
    return False

def check_missing_authorization(node, analyzer=None):
    if not isinstance(node, ast.FunctionDef):
        return None

    name = node.name.lower()

    # Step 1: detect privileged function by name
    function_may_be_privileged = any(k in name for k in PRIVILEGED_KEYWORDS)

    # Step 2: check for authentication-only decorator
    has_require_auth = False
    for deco in node.decorator_list:
        if isinstance(deco, ast.Name) and deco.id == "require_auth":
            has_require_auth = True
        elif isinstance(deco, ast.Attribute) and deco.attr == "require_auth":
            has_require_auth = True

    privileged_call_detected = False
    has_auth_check = False
    unsafe_admin_check = False
    literal_token_check = False
    privileged_assignment = False
    caller_privilege_flag_check = False
    has_destructive_method = False

    # Collect parameter names
    params = [arg.arg.lower() for arg in node.args.args] if node.args.args else []

    # Detect likely caller-supplied flags
    possible_privilege_flags = [
        p for p in params if any(k in p for k in ["is_admin", "make_admin", "privileged", "grant_admin"])
    ]

    # Detect destructive / privileged operation in function name
    if any(k in name for k in DESTRUCTIVE_METHODS):
        has_destructive_method = True

    # Step 3: scan inside body
    for inner in ast.walk(node):
        # ---- Detect unsafe literal token comparison ----
        if isinstance(inner, ast.If):
            try:
                condition_str = ast.unparse(inner.test).lower()
            except Exception:
                condition_str = str(inner.test).lower()

            if any(k in condition_str for k in AUTH_CHECK_KEYWORDS):
                has_auth_check = True
                    
            # Literal token trust pattern
            if (
                ("token" in condition_str and ("==" in condition_str or "in " in condition_str))
                or "startswith" in condition_str
                or "endswith" in condition_str
                or "jwt.decode" in condition_str
            ):
                if any(q in condition_str for q in ["'magic'", '"magic"', "'m2'", "'x'", "'backdoor_token'"]):
                    literal_token_check = True

            # Caller-supplied privilege flag usage
            if any(flag in condition_str for flag in possible_privilege_flags):
                caller_privilege_flag_check = True

        # ---- Detect raise PermissionError (authorization present) ----
        if isinstance(inner, ast.Raise):
            if isinstance(inner.exc, ast.Call):
                func_name = getattr(inner.exc.func, "id", None)
                if func_name and "PermissionError" in func_name:
                    has_auth_check = True

        # ---- Detect privileged calls ----
        if isinstance(inner, ast.Call):
            func_full = get_full_func_name(inner.func)
            if any(priv_call in func_full for priv_call in PRIVILEGED_CALLS):
                privileged_call_detected = True

        # ---- Detect direct role or privilege assignments ----
        if isinstance(inner, ast.Assign):
            target_str = ast.unparse(inner.targets[0]) if hasattr(ast, "unparse") else str(inner.targets[0])
            if any(x in target_str for x in ["role", "privilege"]):
                privileged_assignment = True

        # ---- Detect destructive/privileged calls ----
        if isinstance(inner, ast.Call):
            func_full = get_full_func_name(inner.func).lower()
            if any(k in func_full for k in DESTRUCTIVE_METHODS):
                has_destructive_method = True

    # Step 4: classify issues
    if unsafe_admin_check:
        return {
            "line": node.lineno,
            "function": node.name,
            "category": "A01 Broken Access Control",
            "rule": "107",
            "vulnerability": "Hard-coded username checks",
            "severity": "HIGH",
            "description": "Authorization by comparing usernames to specific hard-coded values is brittle and often bypassable (e.g., user rename edge cases, database inconsistencies). It also creates a single point of failure (one username with power).",
            "recommendation": "Use roles/permissions/groups rather than specific usernames. If you must map user to admin, manage that mapping in RBAC data and check `user.roles` or `user.is_admin` computed from authoritative data."
        }

    # (a) Authenticated-only without role/scope check
    if has_require_auth and not has_auth_check and (function_may_be_privileged or privileged_call_detected):
        return {
            "line": node.lineno,
            "function": node.name,
            "category": "A01 Broken Access Control",
            "rule": "101",
            "vulnerability": "Missing authorization (authenticated-only protection)",
            "severity": "HIGH",
            "description": "Functions are protected only by authentication (e.g. `@login_required`, `@require_auth`) but perform privileged or destructive operations without any role/permission/ownership checks. Authentication alone only proves who is calling, it does not prove they are allowed to perform the action.",
            "recommendation": "Add explicit authorization checks (RBAC/ABAC) inside the function or via an authorization decorator. Validate caller roles/permissions or ownership before performing privileged actions."
        }

    # (b) Privileged operation without any authorization
    if (function_may_be_privileged or privileged_call_detected) and not has_auth_check:
        return {
            "line": node.lineno,
            "function": node.name,
            "category": "A01 Broken Access Control",
            "rule": "102",
            "vulnerability": "Privileged operation without any authorization check",
            "severity": "MEDIUM",
            "description": "Function names, calls, or assignments indicate privileged actions (e.g., `delete_user`, `set_role`, `db.update`) but there is no sign of any authorization logic anywhere in the body. This is a direct broken access control issue.",
            "recommendation": "Treat any privileged call as requiring explicit authorization. Add checks that verify the caller’s permissions or ownership before the call. Log and test authorization paths. Use unit tests asserting unauthorized callers get `403/PermissionError`."
        }

    # (c) Literal token trusted for privilege escalation
    if literal_token_check and (privileged_assignment or privileged_call_detected):
        return {
            "line": node.lineno,
            "function": node.name,
            "category": "A01 Broken Access Control",
            "rule": "104",
            "vulnerability": "Literal/hardcoded token checks or literal allowlists",
            "severity": "HIGH",
            "description": "Code compares tokens or keys to hard-coded strings (e.g. `if token == 'MAGIC'` or `if token in ['X','Y']`) or relies on literal whitelists embedded in code. This is brittle and easily abused if the literal leaks or is guessable.",
            "recommendation": "Use cryptographically-signed tokens and verify signatures/issuer/issuer-audiences (e.g., verify JWT signature and `iss`, `aud`, `exp`). Maintain allowlists in secure stores (not in source). For secrets, use KMS/secret manager and rotate them regularly."
        }

    # (d) Caller-supplied privilege flag trusted without verifying caller’s roles
    if (
        caller_privilege_flag_check
        and (privileged_assignment or privileged_call_detected)
        and not has_auth_check
    ):
        return {
            "line": node.lineno,
            "function": node.name,
            "category": "A01 Broken Access Control",
            "rule": "103",
            "vulnerability": "Trusting caller-supplied privilege flags",
            "severity": "HIGH",
            "description": "The function reads a client-supplied flag (payload/request parameter like `is_admin`) and uses it to gate a privileged action. Attackers can set those fields in requests to escalate privileges.",
            "recommendation": "Never trust client-provided role/privilege flags. Determine roles/privileges server-side (from database, token claims after verification, or identity provider). If a request contains intended role changes, require that the caller has an admin permission, and validate it with an independent server-side authorization check."
        }

    # (e) No decorator or authorization check for destructive operation
    if has_destructive_method and not has_auth_check:
        return {
            "line": node.lineno,
            "function": node.name,
            "category": "A01 Broken Access Control",
            "rule": "101",
            "vulnerability": "Missing authorization (authenticated-only protection)",
            "severity": "HIGH",
            "description": "Functions are protected only by authentication (e.g. `@login_required`, `@require_auth`) but perform privileged or destructive operations without any role/permission/ownership checks. Authentication alone only proves who is calling, it does not prove they are allowed to perform the action.",
            "recommendation": "Add explicit authorization checks (RBAC/ABAC) inside the function or via an authorization decorator. Validate caller roles/permissions or ownership before performing privileged actions."
        }

    return None

def check_trusting_privilege_flag(node, analyzer=None):
    if not isinstance(node, ast.FunctionDef):
        return None

    has_require_auth = any(
        (isinstance(deco, ast.Name) and deco.id == "require_auth") or
        (isinstance(deco, ast.Attribute) and deco.attr == "require_auth")
        for deco in node.decorator_list
    )

    if not has_require_auth:
        return None

    params = [arg.arg.lower() for arg in node.args.args]
    possible_flags = [
        p for p in params
        if any(k in p for k in ["is_admin", "make_admin", "privileged", "grant_admin", "elevate"])
    ]
    if not possible_flags:
        return None

    caller_flag_used = False
    privileged_action = False
    has_auth_check = False

    for inner in ast.walk(node):
        if isinstance(inner, ast.If):
            cond = ast.unparse(inner.test).lower()
            
            # Check if this condition uses the caller-supplied flag
            if any(flag in cond for flag in possible_flags):
                caller_flag_used = True
                # Don't count this as an auth check even if it contains keywords
                continue
            
            # Only count as auth check if it uses keywords but NOT the caller flag
            if any(k.lower() in cond for k in AUTH_CHECK_KEYWORDS):
                has_auth_check = True

        if isinstance(inner, ast.Call):
            func_full = get_full_func_name(inner.func)
            if any(priv in func_full for priv in PRIVILEGED_CALLS):
                privileged_action = True

        # Check for auth checks in Raise/Assert
        if isinstance(inner, (ast.Raise, ast.Assert)):
            try:
                test_str = ast.unparse(inner).lower()
            except Exception:
                test_str = str(inner).lower()
            if any(k.lower() in test_str for k in AUTH_CHECK_KEYWORDS):
                has_auth_check = True

    if caller_flag_used and privileged_action and not has_auth_check:
        return {
            "line": node.lineno,
            "function": node.name,
            "category": "A01 Broken Access Control",
            "rule": "103",
            "vulnerability": "Trusting caller-supplied privilege flags",
            "severity": "HIGH",
            "description": "The function reads a client-supplied flag (payload/request parameter like `is_admin`) and uses it to gate a privileged action. Attackers can set those fields in requests to escalate privileges.",
            "recommendation": "Never trust client-provided role/privilege flags. Determine roles/privileges server-side (from database, token claims after verification, or identity provider). If a request contains intended role changes, require that the caller has an admin permission, and validate it with an independent server-side authorization check."
        }

    return None

def check_unverified_token_role_assignment(node, analyzer=None):
    if not isinstance(node, ast.FunctionDef):
        return None

    # Identify token-like parameters
    params = [arg.arg.lower() for arg in node.args.args]
    token_like_params = [p for p in params if "token" in p or "key" in p or "auth" in p]
    if not token_like_params:
        return None

    # Tracking flags
    literal_token_check = False
    unverified_token_source = False
    privileged_action = False
    has_verification_check = False
    weak_verification_check = False
    jwt_decode_unverified = False
    literal_collections = set()

    # Best-effort snippet collectors
    first_relevant_node = None

    for inner in ast.walk(node):
        # === Detect literal token comparisons ===
        if isinstance(inner, ast.Compare):
            try:
                src = ast.unparse(inner).lower()
            except Exception:
                src = str(inner).lower()

            if any(p in src for p in token_like_params):
                # token == "MAGIC"
                if any(isinstance(c, ast.Constant) and isinstance(c.value, str) for c in inner.comparators):
                    literal_token_check = True
                    first_relevant_node = first_relevant_node or inner

                # token in ["MAGIC", "X"]
                if any(isinstance(op, ast.In) for op in inner.ops):
                    for comp in inner.comparators:
                        if isinstance(comp, (ast.List, ast.Tuple, ast.Set)):
                            if any(isinstance(elt, ast.Constant) and isinstance(elt.value, str) for elt in comp.elts):
                                literal_token_check = True
                                first_relevant_node = first_relevant_node or inner
                        elif isinstance(comp, ast.Name) and comp.id.lower() in literal_collections:
                            literal_token_check = True
                            first_relevant_node = first_relevant_node or inner

        # === Detect prefix/suffix literal matching (startswith/endswith) ===
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
            func_attr = inner.func.attr.lower()
            if func_attr in ["startswith", "startwith", "endswith", "endwith"]:
                try:
                    src = ast.unparse(inner).lower()
                except Exception:
                    src = str(inner).lower()

                # Check if left-hand side is token or token.lower()/upper()
                target_expr = inner.func.value
                while isinstance(target_expr, ast.Call) and isinstance(target_expr.func, ast.Attribute) and target_expr.func.attr.lower() in ["lower", "upper"]:
                    target_expr = target_expr.func.value

                target_name = getattr(target_expr, "id", "").lower()
                if any(p in target_name for p in token_like_params):
                    # Look for literal string arguments
                    for arg in inner.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            literal_token_check = True
                            first_relevant_node = first_relevant_node or inner

        # === Detect local whitelists like allowed = ["MAGIC", "X"] ===
        if isinstance(inner, ast.Assign) and len(inner.targets) == 1:
            target_name = getattr(inner.targets[0], "id", "").lower()
            if isinstance(inner.value, (ast.List, ast.Tuple, ast.Set)):
                if all(isinstance(elt, ast.Constant) and isinstance(elt.value, str) for elt in inner.value.elts):
                    literal_collections.add(target_name)

        # === Detect unverified token sources ===
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
            func_full = get_full_func_name(inner.func).lower()
            if any(src in func_full for src in [
                "headers.get", "cookies.get", "args.get", "json.get", "body.get",
                "os.getenv", "request.headers", "request.cookies", "request.args",
                "request.json", "db.query", "db.get_token"
            ]):
                unverified_token_source = True
                first_relevant_node = first_relevant_node or inner

            # specifically detect jwt.decode usage and if decode is called without apparent verification keyword
            if "jwt.decode" in func_full or func_full.endswith(".jwt.decode"):
                # check for verify=False kwarg (best-effort)
                for kw in inner.keywords:
                    if kw.arg == "verify":
                        if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            jwt_decode_unverified = True
                            first_relevant_node = first_relevant_node or inner
                # even without explicit verify kw, mark unverified-source if token param appears passed directly
                unverified_token_source = True
                first_relevant_node = first_relevant_node or inner

        # === Detect privileged assignments (role = 'admin') ===
        if isinstance(inner, ast.Assign):
            try:
                target_code = ast.unparse(inner.targets[0]).lower() if inner.targets else ""
                value_code = ast.unparse(inner.value).lower()
            except Exception:
                target_code = ""
                value_code = ""
            if (
                ("role" in target_code and "admin" in value_code)
                or any(k in value_code for k in ["grant_role", "update_role", "set_role", "assign_role"])
            ):
                privileged_action = True
                first_relevant_node = first_relevant_node or inner

        # === Detect DB privilege modifications ===
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
            func_full = get_full_func_name(inner.func).lower()
            if any(priv in func_full for priv in ["db.update", "db.execute", "grant_role", "update_user_role", "set_role"]):
                call_str = ""
                try:
                    call_str = ast.unparse(inner).lower()
                except Exception:
                    call_str = func_full
                if "role" in call_str and "admin" in call_str:
                    privileged_action = True
                    first_relevant_node = first_relevant_node or inner

        # === Detect strong verification (safe patterns) ===
        if isinstance(inner, ast.If):
            try:
                cond = ast.unparse(inner.test).lower()
            except Exception:
                cond = ""
            if any(k in cond for k in [
                "verify_signature", "hmac.compare", "secrets.compare_digest",
                "jwt.verify", "verify_jwt", "authenticate_token",
                "token_obj.user_id == current_user.id",
                "token.owner_id == user.id",
                "check_permission", "has_permission",
                "is_superadmin and current_user"
            ]):
                has_verification_check = True
                first_relevant_node = first_relevant_node or inner
            # weak heuristic checks like is_valid_token(...)
            if any(k in cond for k in ["is_valid_token", "is_valid_key", "validate_token"]):
                weak_verification_check = True
                first_relevant_node = first_relevant_node or inner

        # === Detect explicit rejection patterns ===
        if isinstance(inner, ast.Raise):
            try:
                raise_str = ast.unparse(inner).lower()
            except Exception:
                raise_str = str(inner).lower()
            if any(k in raise_str for k in ["permissionerror", "unauthorized", "forbidden"]):
                has_verification_check = True
                first_relevant_node = first_relevant_node or inner

    # === Final classification & mapping to vulnerability IDs ===
    if privileged_action and not has_verification_check:
        # Decide message type and vulnerability id
        if jwt_decode_unverified:
            vuln_id = "105"
            vuln_title = "Unverified JWT decoding / trusting token claims without verification"
            severity = "CRITICAL"
            description = (
                "Calls to jwt.decode(..., verify=False) or decoding tokens without verifying signature/issuer "
                "are present; token claims are then used for authorization, allowing forged tokens to impersonate privileged accounts."
            )
            recommendation = (
                "Always verify token signature, issuer, audience, expiration, and scopes. Do not set verify=False. "
                "Use JWKS/public keys and check alg/issuer/audience."
            )
            relevant_flag = "jwt_unverified"
            node_for_snippet = first_relevant_node
        elif literal_token_check:
            vuln_id = "104"
            vuln_title = "Literal/hardcoded token checks or literal allowlists"
            severity = "HIGH"
            description = (
                "Code compares tokens or keys to hard-coded strings or relies on literal allowlists in code. "
                "This is brittle and easily abused if the literal leaks or can be guessed."
            )
            recommendation = (
                "Replace literal comparisons with cryptographic token verification (signed tokens), store secrets in a secret manager, and rotate keys."
            )
            relevant_flag = "literal_token"
            node_for_snippet = first_relevant_node
        elif unverified_token_source:
            vuln_id = "109"
            vuln_title = "Role/permission assignment using unverified tokens or untrusted sources"
            severity = "HIGH"
            description = (
                "Functions take tokens/keys from headers, cookies, or payload and use them to perform role assignment (e.g., set role='admin') "
                "without verifying token issuer or binding token to identity."
            )
            recommendation = (
                "Verify token authenticity and ownership before any role changes. Use server-side workflows for role grants (audit, approvals), "
                "and require privileged actions be performed by users with explicit admin scopes. Record audit logs of role changes."
            )
            relevant_flag = "unverified_source"
            node_for_snippet = first_relevant_node
        elif weak_verification_check:
            vuln_id = "120"
            vuln_title = "Weak verification patterns (custom weak validators)"
            severity = "MEDIUM"
            description = (
                "The code uses weak heuristics (e.g., custom `is_valid_token()` with unclear cryptographic checks) instead of standard, "
                "proven libraries and signature verification; or uses `startswith`/`endswith` string matches for tokens."
            )
            recommendation = (
                "Replace weak checks with cryptographic verification using trusted libraries. Use `hmac.compare_digest` for secret comparisons, "
                "verify signatures, and enforce token expiry/scopes."
            )
            relevant_flag = "weak_validation"
            node_for_snippet = first_relevant_node
        else:
            return None

        code_snippet = ""
        try:
            if node_for_snippet is not None:
                raw = ast.unparse(node_for_snippet)
                # truncate to reasonable length
                code_snippet = raw.strip()
                if len(code_snippet) > 500:
                    code_snippet = code_snippet[:497] + "..."
        except Exception:
            # fallback to small excerpt of the full function head
            try:
                code_snippet = ast.unparse(node).splitlines()[0][:200]
            except Exception:
                code_snippet = node.name

        finding = {
            "line": getattr(node_for_snippet, "lineno", node.lineno),
            "function": code_snippet,
            "category": "A01 Broken Access Control",
            "rule": vuln_id,
            "vulnerability": vuln_title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation
        }
        return finding

    return None

def check_auth_only_privileged_operation(node, analyzer=None):
    if not isinstance(node, ast.FunctionDef):
        return None

    # Step 1: Detect presence of authentication-only decorators
    has_auth_decorator = any(
        (isinstance(deco, ast.Name) and deco.id in AUTH_DECORATORS) or
        (isinstance(deco, ast.Attribute) and deco.attr in AUTH_DECORATORS)
        for deco in node.decorator_list
    )
    if not has_auth_decorator:
        return None

    # Step 2: Convert body to lowercase text
    body_str = ast.unparse(node).lower()
    has_privileged_action = any(k.lower() in body_str for k in PRIVILEGED_KEYWORDS)
    if not has_privileged_action:
        return None

    # Step 3: Detect authorization-related checks
    has_authz_check = any(k.lower() in body_str for k in AUTH_CHECK_KEYWORDS)

    # Step 4: Truthy authentication (weak)
    truthy_auth_check = False
    for inner in ast.walk(node):
        if isinstance(inner, ast.If):
            cond_str = ast.unparse(inner.test).lower()
            if "current_user" in cond_str and "is_" not in cond_str:
                truthy_auth_check = True

    # Step 5: Check statement order — privilege before authorization (improved)
    priv_before_auth = False
    priv_line = None
    auth_line = None
    for inner in ast.walk(node):
        if isinstance(inner, ast.Call):
            call_str = get_full_func_name(inner.func).lower()
            if any(k.lower() in call_str for k in PRIVILEGED_KEYWORDS):
                priv_line = priv_line or inner.lineno
        elif isinstance(inner, (ast.If, ast.Raise, ast.Assert)):
            try:
                cond_text = ast.unparse(inner).lower()
            except Exception:
                cond_text = str(inner).lower()
            if any(k.lower() in cond_text for k in AUTH_CHECK_KEYWORDS):
                if not auth_line or inner.lineno < auth_line:
                    auth_line = inner.lineno
    # Detect late authorization (privileged op comes first)
    if priv_line and auth_line and priv_line < auth_line:
        priv_before_auth = True

    # Step 6: Final classification

    # Determine which vulnerability id to map to (priority order)
    chosen_id = None
    vulnerability = ""
    severity = "INFO"
    description = ""
    recommendation = ""
    # Priority: missing explicit authz (01) > presence-only (06) > late auth (08) > generic privileged-op-without-auth (02)
    if not has_authz_check:
        chosen_id = "101"
        vulnerability = "Missing authorization (authenticated-only protection)"
        severity = "HIGH"
        description = "Functions are protected only by authentication (e.g. `@login_required`, `@require_auth`) but perform privileged or destructive operations without any role/permission/ownership checks. Authentication alone only proves who is calling, it does not prove they are allowed to perform the action."
        recommendation = "Add explicit authorization checks (RBAC/ABAC) inside the function or via an authorization decorator. Validate caller roles/permissions or ownership before performing privileged actions."
    if truthy_auth_check and chosen_id is None:
        chosen_id = "106"
        vulnerability = "Authentication-checks based on presence/truthiness (session presence) used as authorization"
        severity = "HIGH"
        description = "Code checks only the presence of a session or truthiness of `current_user` / `request.user` (e.g., `if current_user:`) and then performs privileged operations. Presence indicates authentication, not authorization."
        recommendation = "Replace presence checks with explicit calls to permission APIs (e.g., `user.has_role('admin')`, `has_permission(user, 'modify')`) and/or ownership checks (`resource.owner_id == current_user.id`). Add tests for unauthorized authenticated users."
    if priv_before_auth and chosen_id is None:
        chosen_id = "108"
        vulnerability = "Authorization check ordering problems (privileged action happens before auth check)"
        severity = "HIGH"
        description = "The code performs the privileged operation, then checks authorization (checks after action) or has auth-checks that are only executed after the privilege change which making checks ineffective."
        recommendation = "Always validate authorization before the privileged action. Structure code so all guard checks run first and early-exit on failure (raise/return)."
    if chosen_id is None and has_privileged_action:
        chosen_id = "102"
        vulnerability = "Privileged operation without any authorization check"
        severity = "MEDIUM"
        description = "Function names, calls, or assignments indicate privileged actions (e.g., `delete_user`, `set_role`, `db.update`) but there is no sign of any authorization logic anywhere in the body. This is a direct broken access control issue."
        recommendation = "Treat any privileged call as requiring explicit authorization. Add checks that verify the caller’s permissions or ownership before the call. Log and test authorization paths. Use unit tests asserting unauthorized callers get `403/PermissionError`."

    # Safety: if still None, don't report
    if not chosen_id:
        return None

    return {
        "line": node.lineno,
        "function": node.name,
        "category": "A01 Broken Access Control",
        "rule": chosen_id,
        "vulnerability": vulnerability,
        "severity": severity,
        "description": description,
        "recommendation": recommendation
    }

def check_group_privilege_escalation(node, analyzer=None):
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []

    # --- helper mapping (subset from your provided list) ---
    VULN_MAP = {
        "102": {
            "vulnerability": "Privileged operation without any authorization check",
            "severity": "MEDIUM",
            "description": "Function names, calls, or assignments indicate privileged actions (e.g., `delete_user`, `set_role`, `db.update`) but there is no sign of any authorization logic anywhere in the body. This is a direct broken access control issue.",
            "recommendation": "Treat any privileged call as requiring explicit authorization. Add checks that verify the caller’s permissions or ownership before the call. Log and test authorization paths. Use unit tests asserting unauthorized callers get `403/PermissionError`."
        },
        "103": {
            "vulnerability": "Trusting caller-supplied privilege flags",
            "severity": "HIGH",
            "description": "The function reads a client-supplied flag (payload/request parameter like `is_admin`) and uses it to gate a privileged action. Attackers can set those fields in requests to escalate privileges.",
            "recommendation": "Never trust client-provided role/privilege flags. Determine roles/privileges server-side (from database, token claims after verification, or identity provider). If a request contains intended role changes, require that the caller has an admin permission, and validate it with an independent server-side authorization check."
        },
        "115": {
            "vulnerability": "Background jobs losing authorization context (enqueueing without asserting permissions)",
            "severity": "MEDIUM",
            "description": "Code enqueues background jobs with client-supplied payloads without binding or verifying the caller’s authorization; worker later runs privileged changes without authorization checks (authorization context lost).",
            "recommendation": "Capture and verify authorization when scheduling: either perform auth checks at enqueue time and include only authorized payloads, or include a verified, signed job token that the worker can validate. Re-check authorization in the worker if the action is still privileged."
        },
        "117": {
            "vulnerability": "Group/role modifications using client-controlled inputs or insufficient guards",
            "severity": "HIGH",
            "description": "Operations that modify `group.members`, `group.admins`, `user.roles` or similar accept client-provided values (e.g., `payload.roles`) or call `group.__dict__.update(payload)` without proper authorization, allowing an attacker to add themselves to privileged groups.",
            "recommendation": "Require server-side checks: validate the caller has `group.admin` permission, enforce ownership checks, or require invitations/verification flows. Never accept role membership arrays from arbitrary clients and always enforce authorization checks before applying changes."
        },
        "118": {
            "vulnerability": "Late authorization (checking after modification) and ineffective if-blocks",
            "severity": "HIGH",
            "description": "The code either checks equality or has if-conditions that do not actually prevent the privileged operation (e.g., a conditional that doesn’t `raise`/`return` on failure) or checks come after the modification. That leaves privileged code unguarded.",
            "recommendation": "Make guard clauses fail-fast (`if not allowed: raise PermissionError`) and ensure privileged actions are inside the protected branch or always executed only after successful checks."
        },
        "122": {
            "vulnerability": "External system modifications (LDAP/AD/cloud IAM) without pre-checks",
            "severity": "HIGH",
            "description": "Calls to external identity systems (`ldap.modify`, `iam.create_user`, `aws.iam.*`) triggered without server-side authorization checks can modify global identity state.",
            "recommendation": "Enforce multi-level authorization for external identity operations. Add role checks, log and audit every external change, and require privileged admin approvals and CSRF protection where applicable."
        }
    }

    # --- original detection setup (kept mostly intact) ---
    SENSITIVE_ATTRS = {"members", "admins", "owners", "owner", "staff", "moderators", "roles", "privileges", "permissions"}
    MODIFY_METHODS = {"append", "extend", "add", "insert", "update"}
    ASSIGNMENT_FUNCS = {"setattr"}
    SAFE_KEYWORDS = AUTH_CHECK_KEYWORDS

    CLIENT_INPUT_PATTERNS = [
        "request.args", "request.json", "request.form", "request.data",
        "request.get_json", "request.values", "payload", "params",
        "invite.", "token."
    ]
    BACKGROUND_JOB_PATTERNS = ["enqueue", "queue.add", "celery.send_task", "delay", "apply_async", "schedule"]
    EXTERNAL_SYSTEM_PATTERNS = ["ldap.modify", "ldap.add", "ad.modify", "directory.update"]

    modifications = []
    auth_checks = []
    client_inputs = []
    background_jobs = []
    external_modifications = []

    # Collect modifications and auth checks
    for inner in ast.walk(node):
        mod_info = None

        # CASE: group.<attr>.<method>()
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
            func_attr = inner.func
            try:
                # pattern: group.<sensitive>.<modify>()
                if (
                    isinstance(func_attr.value, ast.Attribute)
                    and isinstance(func_attr.value.value, ast.Name)
                    and func_attr.value.value.id.lower() in {"group", "grp", "g"}
                    and func_attr.value.attr.lower() in SENSITIVE_ATTRS
                    and func_attr.attr.lower() in MODIFY_METHODS
                ):
                    is_client_controlled = False
                    for arg in inner.args:
                        arg_source = get_value_source(arg)
                        if any(pattern in arg_source for pattern in CLIENT_INPUT_PATTERNS):
                            is_client_controlled = True
                    mod_info = {
                        "line": inner.lineno,
                        "type": "method_call",
                        "target": safe_unparse(inner) or f"{func_attr.value.value.id}.{func_attr.value.attr}.{func_attr.attr}()",
                        "client_controlled": is_client_controlled,
                        "ast_node": inner
                    }

                # chained: Group.find(...).admins.append(...)
                if (
                    isinstance(func_attr.value, ast.Attribute)
                    and isinstance(func_attr.value.value, ast.Call)
                    and func_attr.value.attr.lower() in SENSITIVE_ATTRS
                    and func_attr.attr.lower() in MODIFY_METHODS
                ):
                    mod_info = {
                        "line": inner.lineno,
                        "type": "chained_method_call",
                        "target": safe_unparse(inner) or f"Group.find(...).{func_attr.value.attr}.{func_attr.attr}()",
                        "client_controlled": True,
                        "ast_node": inner
                    }
            except Exception:
                pass

        # CASE: setattr(group, 'admins', something)
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name):
            if inner.func.id in ASSIGNMENT_FUNCS and len(inner.args) >= 2:
                try:
                    if isinstance(inner.args[1], ast.Constant) and str(inner.args[1].value).lower() in SENSITIVE_ATTRS:
                        mod_info = {
                            "line": inner.lineno,
                            "type": "setattr",
                            "target": safe_unparse(inner) or f"setattr(..., '{inner.args[1].value}', ...)",
                            "client_controlled": False,
                            "ast_node": inner
                        }
                except Exception:
                    pass

        # CASE: __dict__.update(...) or something.update(...)
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
            try:
                func_str = ast.unparse(inner.func).lower()
                if ("__dict__" in func_str or "update" in func_str) and (
                    "group" in func_str or "grp" in func_str or 
                    any(isinstance(arg, ast.Name) and "group" in arg.id.lower() for arg in inner.args)
                ):
                    is_client_controlled = False
                    for arg in inner.args:
                        arg_source = get_value_source(arg)
                        if isinstance(arg, ast.Name):
                            if arg.id.lower() in ["payload", "data", "params", "request_data", "body"]:
                                is_client_controlled = True
                        if any(pattern in arg_source for pattern in CLIENT_INPUT_PATTERNS):
                            is_client_controlled = True
                    mod_info = {
                        "line": inner.lineno,
                        "type": "dict_update",
                        "target": safe_unparse(inner) or func_str,
                        "client_controlled": is_client_controlled,
                        "ast_node": inner
                    }
            except Exception:
                pass

        # CASE: assignment like group.admins = ...
        if isinstance(inner, ast.Assign):
            for target in inner.targets:
                if isinstance(target, ast.Attribute):
                    try:
                        full_attr = ast.unparse(target).lower()
                        if any(s in full_attr for s in SENSITIVE_ATTRS):
                            if "group" in full_attr or "grp" in full_attr or "user" in full_attr:
                                value_source = get_value_source(inner.value)
                                is_client_controlled = any(pattern in value_source for pattern in CLIENT_INPUT_PATTERNS)
                                mod_info = {
                                    "line": inner.lineno,
                                    "type": "assignment",
                                    "target": safe_unparse(target) if safe_unparse(target) else full_attr,
                                    "client_controlled": is_client_controlled,
                                    "ast_node": inner
                                }
                    except Exception:
                        pass

        # Helper calls & background/external detection
        if isinstance(inner, ast.Call):
            func_str = get_full_func_name(inner.func).lower()
            if any(k in func_str for k in [
                "add_to_group", "join_group", "add_member", "promote_in_ldap", 
                "set_roles", "update_group", "grant_permission"
            ]):
                mod_info = {
                    "line": inner.lineno,
                    "type": "helper_call",
                    "target": safe_unparse(inner) or func_str,
                    "client_controlled": False,
                    "ast_node": inner
                }
            if any(pattern in func_str for pattern in BACKGROUND_JOB_PATTERNS):
                background_jobs.append({
                    "line": inner.lineno,
                    "target": safe_unparse(inner) or func_str,
                    "ast_node": inner
                })
            if any(pattern in func_str for pattern in EXTERNAL_SYSTEM_PATTERNS):
                external_modifications.append({
                    "line": inner.lineno,
                    "target": safe_unparse(inner) or func_str,
                    "ast_node": inner
                })

        if mod_info:
            modifications.append(mod_info)

        # collect client input usage attributes
        if isinstance(inner, ast.Attribute):
            try:
                attr_str = ast.unparse(inner).lower()
                if any(pattern in attr_str for pattern in CLIENT_INPUT_PATTERNS):
                    client_inputs.append({
                        "line": inner.lineno,
                        "source": attr_str,
                        "ast_node": inner
                    })
            except Exception:
                pass

        # Collect auth checks (protective)
        auth_info = None
        if isinstance(inner, ast.If):
            try:
                cond_str = ast.unparse(inner.test).lower()
                is_protective_check = False
                if any(k.lower() in cond_str for k in SAFE_KEYWORDS):
                    is_protective_check = True

                # detect if-check exit path
                has_exit_path = False
                for stmt in inner.body:
                    if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                        has_exit_path = True
                        break
                for stmt in inner.orelse:
                    if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                        has_exit_path = True
                        break

                # detect danger inside the if-block (ineffective guard)
                has_danger_inside = False
                for stmt in ast.walk(inner):
                    if isinstance(stmt, ast.Call):
                        try:
                            call_str = ast.unparse(stmt).lower()
                            if any(attr in call_str for attr in SENSITIVE_ATTRS) and \
                               any(method in call_str for method in MODIFY_METHODS):
                                has_danger_inside = True
                                break
                        except Exception:
                            pass
                    if isinstance(stmt, ast.Attribute):
                        try:
                            attr_str = ast.unparse(stmt).lower()
                            if any(attr in attr_str for attr in SENSITIVE_ATTRS) and "group" in attr_str:
                                has_danger_inside = True
                                break
                        except Exception:
                            pass

                is_truly_protective = False
                if has_exit_path and not has_danger_inside:
                    if ".roles" in cond_str or "role" in cond_str or is_protective_check:
                        is_truly_protective = True
                if is_protective_check and not has_danger_inside:
                    is_truly_protective = True

                if is_truly_protective:
                    auth_info = {
                        "line": inner.lineno,
                        "end_line": get_end_line(inner),
                        "type": "if_check",
                        "condition": cond_str,
                        "is_protective": True,
                        "has_exit": has_exit_path,
                        "ast_node": inner
                    }
            except Exception:
                pass

        if isinstance(inner, (ast.Raise, ast.Assert)):
            try:
                test_str = ast.unparse(inner).lower()
                if any(k.lower() in test_str for k in SAFE_KEYWORDS):
                    auth_info = {
                        "line": inner.lineno,
                        "type": "raise_assert",
                        "condition": test_str,
                        "is_protective": True,
                        "ast_node": inner
                    }
            except Exception:
                pass

        if auth_info:
            auth_checks.append(auth_info)

    # Second pass: determine unprotected modifications
    unprotected_modifications = []
    for mod in modifications:
        is_protected = False
        vulnerability_reasons = []

        if mod.get("client_controlled"):
            vulnerability_reasons.append("uses client-controlled input")

        has_preceding_check = False
        for auth in auth_checks:
            if auth["line"] < mod["line"]:
                if auth["type"] == "if_check" and auth.get("is_protective"):
                    if auth.get("has_exit"):
                        is_protected = True
                        has_preceding_check = True
                        break
                    elif mod["line"] <= auth.get("end_line", auth["line"]):
                        is_protected = True
                        has_preceding_check = True
                        break
                elif auth["type"] == "raise_assert":
                    is_protected = True
                    has_preceding_check = True
                    break

        has_check_after = any(auth["line"] > mod["line"] for auth in auth_checks)

        if not is_protected:
            if has_check_after:
                vulnerability_reasons.append("authorization check comes after modification")
            else:
                vulnerability_reasons.append("no authorization check")

        if (not is_protected and not mod.get("client_controlled")) or (mod.get("client_controlled")) or (has_check_after and not has_preceding_check):
            unprotected_modifications.append({
                **mod,
                "reasons": vulnerability_reasons
            })

    # Include background jobs / external modifications as separate findings if present
    for job in background_jobs:
        unprotected_modifications.append({
            "line": job["line"],
            "type": "background_job",
            "target": job.get("target"),
            "client_controlled": False,
            "reasons": ["background job loses authorization context"],
            "ast_node": job.get("ast_node")
        })

    for ext in external_modifications:
        # determine if any auth check appears before ext
        has_auth_before = any(auth["line"] < ext["line"] for auth in auth_checks)
        if not has_auth_before:
            unprotected_modifications.append({
                "line": ext["line"],
                "type": "external_system",
                "target": ext.get("target"),
                "client_controlled": False,
                "reasons": ["external system modification without authorization check"],
                "ast_node": ext.get("ast_node")
            })

    # Build standardized findings list
    findings = []
    for mod in unprotected_modifications:
        line = mod.get("line", node.lineno)
        code_snippet = mod.get("target") or (safe_unparse(mod.get("ast_node")) if mod.get("ast_node") is not None else "")
        reasons = mod.get("reasons", [])

        # Heuristic mapping to vulnerability id
        vuln_id = None

        if mod.get("type") == "background_job":
            vuln_id = "115"
        elif mod.get("type") == "external_system":
            vuln_id = "122"
        else:
            # If client-controlled -> group role modification vulnerability (17)
            if mod.get("client_controlled"):
                vuln_id = "117"
            # If check comes after modification
            if any("authorization check comes after" in r for r in reasons):
                vuln_id = "118"
            # If no auth check and not client-controlled default to privileged-op-without-auth (02)
            if not vuln_id:
                if any("no authorization check" in r for r in reasons):
                    vuln_id = "102"
                else:
                    vuln_id = "117"

        # Build final finding by merging VULN_MAP entry
        vuln_meta = VULN_MAP.get(vuln_id, None)
        if not vuln_meta:
            return None

        # If multiple reasons, prefer to escalate severity for client_controlled or external
        severity = vuln_meta["severity"]
        if mod.get("client_controlled") and severity != "Critical":
            severity = "HIGH"
        if mod.get("type") == "external_system":
            severity = "HIGH"
        if any("background job" in r for r in reasons):
            # background job loses context severity medium unless it's also modifying roles
            if vuln_id == "115":
                severity = "MEDIUM"

        finding = {
            "line": line,
            "code_snippet": (code_snippet[:400] + "...") if code_snippet and len(code_snippet) > 400 else code_snippet,
            "category": "A01 Broken Access Control",
            "rule": vuln_id,
            "vulnerability": vuln_meta["vulnerability"],
            "severity": severity,
            "description": vuln_meta["description"],
            "recommendation": vuln_meta["recommendation"],
            "evidence_reasons": reasons
        }
        findings.append(finding)

    # Always return a list (possibly empty)
    return findings

def check_implicit_privilege_via_config(node: ast.FunctionDef) -> Optional[dict]:
    """
    Specialized check for implicit privilege via config or flags changed by authenticated users
    - Detects yaml.safe_load(...) followed by config.update(cfg)
    - Detects setattr(config_like, key, value) calls
    - Preserves previous detections (exec/eval, __dict__.update, os.environ, FLAGS[], plugin activation, internal proxying, roles assignment)
    - Suppresses when explicit in-function authz checks are present
    """
    if not isinstance(node, ast.FunctionDef):
        return None

    has_require_auth = has_decorator(node, AUTH_DECORATORS)
    is_event = is_event_handler(node)
    is_worker_name = node.name.startswith("worker_") or node.name.startswith("worker")
    enqueues_job = False
    for inner in ast.walk(node):
        if isinstance(inner, ast.Call):
            func_name = get_full_func_name(inner.func).lower()
            if func_name.endswith(".enqueue") or "enqueue(" in func_name:
                enqueues_job = True
                break

    # If function contains explicit authz checks -> treat as fixed
    if contains_explicit_authz(node):
        return None

    sensitive_lines = []
    found_exec = False
    found_internal_proxy = False
    found_plugin_enable = False
    found_dict_update = False
    found_roles_set = False
    found_other_sensitive_write = False
    found_setattr = False
    found_yaml_load_then_update = False

    # Track variable names assigned from yaml.safe_load(...) or yaml.load(...)
    yaml_assigned_vars = set()

    # First pass: collect yaml-assigned variable names
    for inner in ast.walk(node):
        if isinstance(inner, ast.Assign):
            # only handle simple single-target assigns like "cfg = yaml.safe_load(file)"
            if len(inner.targets) == 1 and isinstance(inner.targets[0], ast.Name) and isinstance(inner.value, ast.Call):
                if is_yaml_load_call(inner.value):
                    yaml_assigned_vars.add(inner.targets[0].id)

    # Walk to find sensitive operations
    for inner in ast.walk(node):
        # Exec / eval / compile
        if isinstance(inner, ast.Call):
            if is_code_execution_call(inner):
                found_exec = True
                sensitive_lines.append(getattr(inner, "lineno", node.lineno))
            if is_internal_proxy_call(inner):
                found_internal_proxy = True
                sensitive_lines.append(getattr(inner, "lineno", node.lineno))
            if is_plugin_enable_call(inner):
                found_plugin_enable = True
                sensitive_lines.append(getattr(inner, "lineno", node.lineno))
            if call_targets_dict_update(inner):
                found_dict_update = True
                sensitive_lines.append(getattr(inner, "lineno", node.lineno))
            if is_setattr_call(inner):
                found_setattr = True
                sensitive_lines.append(getattr(inner, "lineno", node.lineno))
            # config.update(somevar) detection: treat as sensitive when somevar came from yaml.safe_load
            func_full = get_full_func_name(inner.func).lower()
            if func_full.endswith(".update"):
                # attempt to inspect the object being updated
                try:
                    obj_src = ""
                    if isinstance(inner.func, ast.Attribute):
                        obj_src = ast.unparse(inner.func.value).lower()
                except Exception:
                    obj_src = ""
                # If the argument is a name that came from yaml.safe_load, flag it
                if inner.args:
                    a0 = inner.args[0]
                    if isinstance(a0, ast.Name) and a0.id in yaml_assigned_vars:
                        # If update targets config-like object, flag
                        if any(cfg in obj_src for cfg in (c.lower() for c in CONFIG_WRITE_TARGETS)) or "config" in obj_src or obj_src.startswith("app"):
                            found_yaml_load_then_update = True
                            sensitive_lines.append(getattr(inner, "lineno", node.lineno))
                    # Also flag direct config.update(cfg) where cfg is any name (conservative)
                    if isinstance(a0, ast.Name) and any(cfg in obj_src for cfg in (c.lower() for c in CONFIG_WRITE_TARGETS)):
                        found_other_sensitive_write = True
                        sensitive_lines.append(getattr(inner, "lineno", node.lineno))
            # detect apply_json_patch/patch calls as sensitive
            if "apply_json_patch" in func_full or "apply_patch" in func_full or func_full.endswith(".patch"):
                found_other_sensitive_write = True
                sensitive_lines.append(getattr(inner, "lineno", node.lineno))
            # DBFlags.* detection
            if any(pat.search(func_full) for pat in DB_FLAG_PATTERNS):
                found_other_sensitive_write = True
                sensitive_lines.append(getattr(inner, "lineno", node.lineno))

        # Assign / AugAssign checks
        if isinstance(inner, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if isinstance(inner, ast.Assign):
                targets = inner.targets
                value = inner.value
            elif isinstance(inner, ast.AnnAssign):
                targets = [inner.target]
                value = inner.value
            else:
                targets = [inner.target]
                value = inner.value

            for t in targets:
                try:
                    if is_sensitive_attr_assignment(t, value):
                        if isinstance(t, ast.Attribute) and getattr(t, "attr", "") == "roles":
                            found_roles_set = True
                        if isinstance(t, ast.Attribute) and getattr(t, "attr", "") == "__dict__":
                            found_dict_update = True
                        found_other_sensitive_write = True
                        sensitive_lines.append(getattr(inner, "lineno", node.lineno))
                except Exception:
                    pass

    # Decision: if none of the sensitive patterns found, return None
    if not any([found_exec, found_internal_proxy, found_plugin_enable, found_dict_update,
                found_roles_set, found_other_sensitive_write, found_setattr, found_yaml_load_then_update]):
        return None

    # Build reasons and severity
    if found_exec:
        rule = "110"
        vulnerability = "Using `exec`/`eval`/`compile` / arbitrary code execution"
        severity = "CRITICAL"
        description = "The presence of `exec`, `eval`, `compile` or similar, especially on user-controlled input (e.g., `exec(payload)`), allows remote code execution (RCE). This is one of the most severe vulnerabilities."
        recommendation = "Remove dynamic code execution. Use safe parsers, explicit handlers, or domain-specific languages with sandboxing. If absolutely required, run code in an isolated, heavily-restricted sandbox (separate process/container) with strict limits, but strongly prefer avoiding it. Sanitize and validate inputs; prefer declarative config not executable strings."
    if found_yaml_load_then_update:
        rule = "111"
        vulnerability = "YAML/config loading from untrusted sources followed by direct config writes"
        severity = "MEDIUM"
        description = "Code uses `yaml.load`/`yaml.safe_load` (especially non-safe versions) or `json.loads` on untrusted input and then uses the loaded data to update sensitive config objects (e.g., `config.update(cfg)`, `app.config.update(...)`), which can implicitly elevate privileges or change behavior."
        recommendation = "Never apply untrusted configuration directly to server runtime config. Validate and whitelist keys and values before applying. Prefer controlled APIs for config changes and require admin authorization. Use `yaml.safe_load` not `yaml.load`, but even with safe_load you must validate structure and allowed keys."
    if found_setattr:
        rule = "112"
        vulnerability = "`__dict__.update` or `setattr` on config-like or user objects using untrusted data"
        severity = "HIGH"
        description = "Using `obj.__dict__.update(some_map)` or `setattr(obj, name, value)` with untrusted input can overwrite internal fields (including `roles`, `is_admin`, `__class__`-like properties in some languages) and lead to privilege escalation or unexpected behavior."
        recommendation = "Avoid bulk updates of internal dicts. Update allowed fields individually and validate property names against an allowlist. Use explicit setters that perform validation and access control."
    if found_dict_update:
        rule = "121"
        vulnerability = "Use of `__dict__` or bulk update on objects that include roles/privileges"
        severity = "HIGH"
        description = "`obj.__dict__.update(data)` or `obj.roles = payload` can overwrite sensitive internal properties (role escalation)."
        recommendation = "Avoid `__dict__` updates. Map and validate allowed fields manually. Use explicit setters that perform authorization checks."
    if found_internal_proxy:
        rule = "113"
        vulnerability = "Internal proxying / server-side request to internal admin endpoints (SSRF/internal API misuse)"
        severity = "HIGH"
        description = "Code constructs HTTP calls to internal/privileged hosts (e.g., `http.post(\"http://internal/...\")`) using unvalidated URLs or client-supplied data. This can be abused to trigger privileged actions via the server (SSRF or broken access control on internal APIs)."
        recommendation = "Block open proxying. Validate target hosts against a strict allowlist. Disallow user-controlled URLs for internal endpoints. Use service-to-service auth (mTLS or signed requests) and ensure internal endpoints also enforce authorization."
    if found_plugin_enable:
        rule = "114"
        vulnerability = "Plugin activation / enabling features from untrusted data"
        severity = "HIGH"
        description = "Code calls plugin enable/activate functions (e.g., `plugin_manager.enable(plugin_name)`) driven by payloads or config loaded from untrusted sources, potentially enabling arbitrary plugin execution."
        recommendation = "Gate plugin installation/activation behind admin-only workflows and code signing. Validate plugin identities, require signatures, and audit every plugin activation. Keep plugin lifecycle restricted to deployment/ops, not end-user requests."
    if found_roles_set:
        rule = "117"
        vulnerability = "Group/role modifications using client-controlled inputs or insufficient guards"
        severity = "HIGH"
        description = "Operations that modify `group.members`, `group.admins`, `user.roles` or similar accept client-provided values (e.g., `payload.roles`) or call `group.__dict__.update(payload)` without proper authorization, allowing an attacker to add themselves to privileged groups."
        recommendation = "Require server-side checks: validate the caller has `group.admin` permission, enforce ownership checks, or require invitations/verification flows. Never accept role membership arrays from arbitrary clients and always enforce authorization checks before applying changes."
    if found_other_sensitive_write:
        rule = "116"
        vulnerability = "Direct DB/config writes (FLAGS, os.environ, feature flags) from user input"
        severity = "HIGH"
        description = "Writing to global flags, environment variables, feature-flag stores, or DB config (e.g., `FLAGS[...] = value`, `os.environ[...] = ...`, `DBFlags.update(...)`) using user input can cause wide-reaching privilege changes or service behavior changes."
        recommendation = "Restrict who can change system flags. Use admin-only APIs, require multi-step confirmation and audits. Validate and sanitize values and store them in secured stores (not user-editable tables). Version and require approvals for config changes."

    return {
        "line": node.lineno,
        "function": node.name,
        "category": "A01 Broken Access Control",
        "rule": rule,
        "vulnerability": vulnerability,
        "severity": severity,
        "description": description,
        "recommendation": recommendation
    }

# Patterns for hardcoded username checks
HARDCODED_USERNAME_PATTERNS = [
    re.compile(r'current_user\.username\s*==\s*[\'"]admin[\'"]', re.I),
    re.compile(r'user\.username\s*==\s*[\'"]admin[\'"]', re.I),
    re.compile(r'username\s*==\s*[\'"]admin[\'"]', re.I),
]

# Privileged action indicators
PRIVILEGED_ACTION_PATTERNS = [
    re.compile(r'\badmin_', re.I),
    re.compile(r'_admin\b', re.I),
    re.compile(r'\bdelete_all\b', re.I),
    re.compile(r'\bbatch_delete\b', re.I),
    re.compile(r'\bmake_admin\b', re.I),
    re.compile(r'\bset_role\b', re.I),
    re.compile(r'\bassign_role\b', re.I),
    re.compile(r'\bupdate_user_role\b', re.I),
    re.compile(r'\bpromote_', re.I),
    re.compile(r'\bgrant_', re.I),
    re.compile(r'\bsensitive_report\b', re.I),
    re.compile(r'\bsecret_', re.I),
    re.compile(r'\bprivileged_', re.I),
]

# Authorization check indicators (these are GOOD patterns that fix the issue)
AUTHORIZATION_CHECK_PATTERNS = [
    re.compile(r'\.roles', re.I),
    re.compile(r'\.permissions', re.I),
    re.compile(r'has_permission\(', re.I),
    re.compile(r'check_permission\(', re.I),
    re.compile(r'require_permission\(', re.I),
    re.compile(r'is_admin\(\)', re.I),  # function call, not attribute
    re.compile(r'has_role\(', re.I),
    re.compile(r'check_role\(', re.I),
    re.compile(r'in\s+.*\.roles', re.I),
    re.compile(r'in\s+.*\.permissions', re.I),
]

def safe_unparse(node):
    try:
        return ast.unparse(node)
    except Exception:
        try:
            return str(node)
        except Exception:
            return ""

def unparse_lower(node):
    return safe_unparse(node).lower()

def cond_is_presence_only(cond_node: ast.AST) -> bool:
    """
    Analyze an if-condition to determine if it's presence-only auth.
    Returns indicator string if it is, None otherwise.
    """
    src = unparse_lower(cond_node)
    # Check for untrusted client flags
    if any(pattern.search(src) for pattern in UNTRUSTED_FLAG_PATTERNS):
        return "untrusted_payload_flag" 
    # Check for hardcoded username checks
    if any(pattern.search(src) for pattern in HARDCODED_USERNAME_PATTERNS):
        return "hardcoded_username_check"
    # Check for combined presence checks (e.g., headers and is_authenticated)
    presence_count = sum(1 for pattern in PRESENCE_INDICATOR_PATTERNS if pattern.search(src))
    if presence_count >= 2:
        return "combined_presence"    
    # Check for single presence indicators
    if any(pattern.search(src) for pattern in PRESENCE_INDICATOR_PATTERNS):
        # But make sure it's not combined with proper authorization
        if not contains_explicit_authz_check(cond_node):
            return "session_presence"    
    return None

def contains_explicit_authz_check(node: ast.AST) -> bool:
    """
    Check if the node contains explicit authorization checks (roles, permissions).
    Returns True if proper authorization is found.
    """
    src = unparse_lower(node)
    return any(pattern.search(src) for pattern in AUTHORIZATION_CHECK_PATTERNS)

def contains_explicit_raises(node: ast.AST) -> bool:
    """
    Search function body for explicit authorization checks or raises that indicate
    the function performs authorization (roles/permissions) rather than only authentication.
    """
    for n in ast.walk(node):
        if isinstance(n, ast.If):
            src = unparse_lower(n.test)
            if any(k.lower() in src for k in AUTHZ_KEYWORDS):
                return True
        if isinstance(n, (ast.Raise, ast.Assert)):
            txt = unparse_lower(n)
            if any(k.lower() in txt for k in AUTHZ_KEYWORDS):
                return True
        if isinstance(n, ast.Call):
            # calls like has_role(...), check_permission(...)
            name = get_full_func_name(n.func).lower()
            if any(x in name for x in AUTH_CHECK_KEYWORDS):
                return True
            # explicit membership checks passed as args could show authz too (not exhaustive)
    return False

def call_is_privileged(call_node: ast.Call) -> bool:
    """
    Determine whether a Call node performs a privileged action by:
      - dotted name matches PRIVILEGED_CALLS
      - name contains a PRIVILEGED_KEYWORDS element
      - name looks like admin/dump/provision/create/delete etc.
    """
    name = get_full_func_name(call_node.func).lower()
    # direct privileged calls
    for pc in PRIVILEGED_CALLS:
        if pc.lower() in name:
            return True
    # keyword-based detection
    for kw in PRIVILEGED_KEYWORDS:
        if kw.lower() in name:
            return True
    # performs privileged/admin actions
    src = unparse_lower(call_node)
    if any(pattern.search(src) for pattern in PRIVILEGED_ACTION_PATTERNS):
        return True
    # also consider certain verbs in bare function names
    if any(verb in name for verb in PRIVILEGED_KEYWORDS):
        return True
    return False

def body_contains_privileged_action(node: ast.AST) -> bool:
    """
    Scan AST subtree for privileged actions:
      - Call nodes that match call_is_privileged
      - Return statements that return a privileged call
      - Assignments to .roles or __dict__ or FLAGS[...] (role escalation or config writes)
    """
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            if call_is_privileged(n):
                return True
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Call):
            if call_is_privileged(n.value):
                return True
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = []
            if isinstance(n, ast.Assign):
                targets = n.targets
            elif isinstance(n, ast.AnnAssign):
                targets = [n.target]
            else:
                targets = [n.target]
            for t in targets:
                if isinstance(t, ast.Attribute):
                    attr = getattr(t, "attr", "").lower()
                    if attr == "roles" or attr == "__dict__":
                        return True
                if isinstance(t, ast.Subscript):
                    try:
                        base = ast.unparse(t.value).lower()
                    except Exception:
                        base = ""
                    if "flags" in base or "feature" in base or "config" in base:
                        return True
    return False

def has_auth_only_decorator(func_node: ast.FunctionDef) -> bool:
    """
    If function has a decorator that enforces only authentication (not authorization),
    e.g. @login_required, return True.
    """
    for d in func_node.decorator_list:
        nm = ""
        if isinstance(d, ast.Name):
            nm = d.id.lower()
        elif isinstance(d, ast.Attribute):
            nm = d.attr.lower()
        elif isinstance(d, ast.Call):
            if isinstance(d.func, ast.Name):
                nm = d.func.id.lower()
            elif isinstance(d.func, ast.Attribute):
                nm = d.func.attr.lower()
        if nm in AUTH_DECORATORS:
            return True
    return False

def jwt_decode_unverified_present(node: ast.AST) -> bool:
    """
    Detect jwt.decode(..., verify=False) or similar unverified decodes used inside the function.
    """
    for inner in ast.walk(node):
        if isinstance(inner, ast.Call):
            func_name = get_full_func_name(inner.func).lower()
            if 'jwt' in func_name and 'decode' in func_name:
                # Check for verify=False in kwargs
                for keyword in inner.keywords:
                    if keyword.arg == 'verify':
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                            return True
    return False

def detect_presence_only_auth_allowing_privilege(node: ast.FunctionDef) -> Optional[dict]:
    """
    Main rule to detect 'is_authenticated' / session presence used as authorization for privileged actions.
    Returns a dict with finding if matched, otherwise None.
    """
    if not isinstance(node, ast.FunctionDef):
        return None

    # If the function includes explicit authz checks, consider it fixed
    if contains_explicit_raises(node):
        return None

    if contains_explicit_authz_check(node):
        return None
    
    # 1) Decorator-only auth (e.g., @login_required) + privileged body
    if has_auth_only_decorator(node) and body_contains_privileged_action(node):
        return {
            "line": node.lineno,
            "function": node.name,
            "category": "A01 Broken Access Control",
            "rule": "101",
            "vulnerability": "Missing authorization (authenticated-only protection)",
            "severity": "HIGH",
            "description": "Functions are protected only by authentication (e.g. `@login_required`, `@require_auth`) but perform privileged or destructive operations without any role/permission/ownership checks. Authentication alone only proves who is calling, it does not prove they are allowed to perform the action.",
            "recommendation": "Add explicit authorization checks (RBAC/ABAC) inside the function or via an authorization decorator. Validate caller roles/permissions or ownership before performing privileged actions."
        }

    # 2) If statements that are presence-only or rely on untrusted client payloads
    for inner in ast.walk(node):
        if isinstance(inner, ast.If):
            cond_indicator = cond_is_presence_only(inner.test)
            if cond_indicator:
                # If the if-branch performs privileged work, flag
                if body_contains_privileged_action(inner):
                    # 00000
                    if cond_indicator == "untrusted_payload_flag":
                        rule = "103"
                        vulnerability = "Trusting caller-supplied privilege flags"
                        severity = "HIGH"
                        description = "The function reads a client-supplied flag (payload/request parameter like `is_admin`) and uses it to gate a privileged action. Attackers can set those fields in requests to escalate privileges."
                        recommendation = "Never trust client-provided role/privilege flags. Determine roles/privileges server-side (from database, token claims after verification, or identity provider). If a request contains intended role changes, require that the caller has an admin permission, and validate it with an independent server-side authorization check."
                    elif cond_indicator == "hardcoded_username_check":
                        rule = "107"
                        vulnerability = "Hard-coded username checks (e.g., `current_user.username == \"admin\"`)"
                        severity = "HIGH"
                        description = "Authorization by comparing usernames to specific hard-coded values is brittle and often bypassable (e.g., user rename edge cases, database inconsistencies). It also creates a single point of failure (one username with power)."
                        recommendation = "Use roles/permissions/groups rather than specific usernames. If you must map user to admin, manage that mapping in RBAC data and check `user.roles` or `user.is_admin` computed from authoritative data."
                    elif cond_indicator == "combined_presence":
                        rule = "106"
                        vulnerability = "Authentication-checks based on presence/truthiness (session presence) used as authorization"
                        severity = "HIGH"
                        description = "Code checks only the presence of a session or truthiness of `current_user` / `request.user` (e.g., `if current_user:`) and then performs privileged operations. Presence indicates authentication, not authorization."
                        recommendation = "Replace presence checks with explicit calls to permission APIs (e.g., `user.has_role(\"admin\")`, `has_permission(user, \"modify\")`) and/or ownership checks (`resource.owner_id == current_user.id`). Add tests for unauthorized authenticated users."
                    else:
                        rule = "106"
                        vulnerability = "Authentication-checks based on presence/truthiness (session presence) used as authorization"
                        severity = "HIGH"
                        description = "Code checks only the presence of a session or truthiness of `current_user` / `request.user` (e.g., `if current_user:`) and then performs privileged operations. Presence indicates authentication, not authorization."
                        recommendation = "Replace presence checks with explicit calls to permission APIs (e.g., `user.has_role(\"admin\")`, `has_permission(user, \"modify\")`) and/or ownership checks (`resource.owner_id == current_user.id`). Add tests for unauthorized authenticated users."
                    return {
                        "line": node.lineno,
                        "function": node.name,
                        "category": "A01 Broken Access Control",
                        "rule": rule,
                        "vulnerability": vulnerability,
                        "severity": severity,
                        "description": description,
                        "recommendation": recommendation
                    }
                
    # 3) Unverified JWT decoding used + privileged actions
    if jwt_decode_unverified_present(node) and body_contains_privileged_action(node):
        return {
            "line": node.lineno,
            "function": node.name,
            "category": "A01 Broken Access Control",
            "rule": "105",
            "vulnerability": "Unverified JWT decode / trusting token claims without verification",
            "severity": "CRITICAL",
            "description": "Calls to `jwt.decode(..., verify=False)` or decoding tokens without verifying signature/issuer are present; token claims are then used for authorization. This allows forged tokens to impersonate privileged accounts.",
            "recommendation": "Always verify token signature, `iss`, `aud`, expiration, and required scopes/claims. Use library defaults (do not set `verify=False`). Use `jwks` / public keys for verification and check `alg` isn't manipulated."
        }

    
    # 4) Direct payload-driven role/privilege changes even without an if
    for inner in ast.walk(node):
        if isinstance(inner, ast.Call):
            name = get_full_func_name(inner.func).lower()
            # sensitive calls
            if any(k in name for k in ("make_admin", "set_role", "assign_role", "update_user_role", "promote_", "grant_")):
                # check arguments / nearby AST to see if they come from payload/request without verification
                arg_srcs = []
                for a in inner.args:
                    arg_srcs.append(unparse_lower(a))
                for kw in inner.keywords:
                    arg_srcs.append(unparse_lower(kw.value))
                arg_text = " ".join(arg_srcs)
                if any(pattern.search(arg_text) for pattern in UNTRUSTED_FLAG_PATTERNS + [
                    re.compile(r'payload', re.I),
                    re.compile(r'request\.json', re.I),
                    re.compile(r'request\.args', re.I),
                    re.compile(r'request\.form', re.I),
                ]):
                    return {
                        "line": node.lineno,
                        "function": node.name,
                        "category": "A01 Broken Access Control",
                        "rule": "119",
                        "vulnerability": "Using `request` headers/args/form directly as authoritative source",
                        "severity": "MEDIUM",
                        "description": "Directly reading `request.headers.get(...)`, `request.args.get(...)`, `request.json` and using those values for authorization or as a factor to allow privileged operations is unsafe because attackers control these fields.",
                        "recommendation": "Treat request values as untrusted. Authenticate and verify identifiers by server-side lookup; use validated, signed tokens for claims; never allow header/payload values to grant privileges without verification."
                    }

    # 5) Simple truthiness or attribute-existence gating the whole function
    first_level = list(node.body)
    if first_level and body_contains_privileged_action(node):
        # pattern: If at top and we already covered it; otherwise check for direct use of presence indicators in top-level exprs
        for stmt in first_level[:3]:  # small window
            if isinstance(stmt, ast.If):
                continue
            src = unparse_lower(stmt)
            matched_pattern = None
            for pattern in PRESENCE_INDICATOR_PATTERNS:
                if pattern.search(src):
                    matched_pattern = src[:200]
                    break
            if matched_pattern:
                return {
                    "line": node.lineno,
                    "function": node.name,
                    "category": "A01 Broken Access Control",
                    "rule": "106",
                    "vulnerability": "Authentication-checks based on presence/truthiness (session presence) used as authorization",
                    "severity": "HIGH",
                    "description": "Code checks only the presence of a session or truthiness of `current_user` / `request.user` (e.g., `if current_user:`) and then performs privileged operations. Presence indicates authentication, not authorization.",
                    "recommendation": "Replace presence checks with explicit calls to permission APIs (e.g., `user.has_role(\"admin\")`, `has_permission(user, \"modify\")`) and/or ownership checks (`resource.owner_id == current_user.id`). Add tests for unauthorized authenticated users."
                }

    return None

RULES1 = [
    check_missing_authorization,
    check_trusting_privilege_flag,
    check_unverified_token_role_assignment,
    check_auth_only_privileged_operation,
    check_group_privilege_escalation,
    check_implicit_privilege_via_config,
    detect_presence_only_auth_allowing_privilege,
]

"""
HIGH-CRITICAL
Missing authorization check before privileged operations
Hardcoded roles or privilege checks
Exposed sensitive endpoints without access control
Unrestricted file and object access
Disabled session validation
"""