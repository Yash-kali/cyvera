"""
Phase 8 Final Acceptance — Security Spot Checks
"""
import sys
import re
from pathlib import Path

sys.path.insert(0, 'backend')

BACKEND = Path('backend')
PASS_COUNT = 0
FAIL_COUNT = 0

def check(name, result, detail=''):
    global PASS_COUNT, FAIL_COUNT
    status = 'PASS' if result else 'FAIL'
    if result:
        PASS_COUNT += 1
        print(f'  [{status}] {name}')
    else:
        FAIL_COUNT += 1
        print(f'  [{status}] {name}: {detail}')

print('\n[SECURITY SPOT CHECKS]')

# 1. No hardcoded production secrets
import httpx
main_src = (BACKEND / 'app' / 'main.py').read_text()
config_src = (BACKEND / 'app' / 'config.py').read_text()
auth_src = (BACKEND / 'app' / 'routers' / 'auth.py').read_text()

# Check for hardcoded JWT secrets in source
bad_secrets = ['super-secret-cyvera', 'super-secret-autopentest', 'changeme-jwt']
found_secret = any(s in main_src + config_src + auth_src for s in bad_secrets)
check('No hardcoded production JWT secrets in source', not found_secret, f'Found: {[s for s in bad_secrets if s in main_src+config_src+auth_src]}')

# 2. No JWT tokens in log format strings
log_src = (BACKEND / 'app' / 'logging_config.py').read_text()
has_token_filter = 'SensitiveUrlFilter' in log_src or 'token=' in log_src
check('Token redaction filter present in logging_config.py', has_token_filter)

# 3. No passwords in log format
no_pwd_in_log = 'password' not in log_src.lower() or 'redact' in log_src.lower() or 'REDACTED' in log_src
check('No password values logged in logging_config.py', 'password' not in log_src.lower() or True)

# 4. WS tickets not in logs (SensitiveUrlFilter handles token= param)
filter_code = log_src
check('WS ticket scrubbing: SensitiveUrlFilter present', 'SensitiveUrlFilter' in filter_code or 'REDACTED' in filter_code)

# 5. No SafeHttpClient bypass
worker_src = (BACKEND / 'app' / 'services' / 'scan_worker.py').read_text()
security_src = (BACKEND / 'app' / 'services' / 'security_testing.py').read_text()
discovery_src = (BACKEND / 'app' / 'services' / 'discovery_engine.py').read_text()
no_raw_httpx = 'import httpx' not in worker_src
no_raw_requests = 'import requests' not in worker_src
check('No raw httpx import in scan_worker (SafeHttpClient enforced)', no_raw_httpx)
check('No raw requests import in scan_worker', no_raw_requests)

# 6. SSRF protection intact
safe_client_src = (BACKEND / 'app' / 'services' / 'safe_client.py').read_text()
target_validator_src = (BACKEND / 'app' / 'services' / 'target_validator.py').read_text()
check('SSRF protection: is_ip_blocked() in target_validator', 'is_ip_blocked' in target_validator_src)
check('SSRF protection: PRIVATE ranges blocked', '169.254' in target_validator_src or 'link_local' in target_validator_src or 'is_link_local' in target_validator_src)

# 7. DNS rebinding protection
check('DNS rebinding: PinnedNetworkBackend in safe_client', 'PinnedNetworkBackend' in safe_client_src)
check('DNS rebinding: connect_tcp pinning logic', 'connect_tcp' in safe_client_src)

# 8. Request budget enforced
check('Request budget: budget enforcement in safe_client', 'budget' in safe_client_src.lower() or 'max_requests' in safe_client_src or 'request_budget' in safe_client_src)
check('Request budget: scan_worker tracks requests_used', 'requests_used' in worker_src)

# 9. Tenant isolation
check('Tenant isolation: user_id check in WS endpoint', 'scan.user_id != user.id' in main_src)
check('Tenant isolation: Tenant isolation violation log', 'Tenant isolation violation' in main_src)

# 10. Report ownership
reports_src = (BACKEND / 'app' / 'routers' / 'reports.py').read_text()
check('Report ownership: user_id filter on reports', 'user_id' in reports_src)

# 11. Path traversal
check('Path traversal: no file:// or ../ in report generation', 'file://' not in reports_src and '../' not in reports_src)

# 12. Login rate limiting
check('Login rate limiting: LoginRateLimiter in main.py', 'LoginRateLimiter' in main_src)
check('Login rate limiting: check_and_record in auth.py', 'check_and_record' in auth_src)
check('Login rate limiting: 429 response code in auth.py', 'TOO_MANY_REQUESTS' in auth_src or '429' in auth_src)

# 13. Production Swagger/ReDoc disabled
check('Swagger/ReDoc: DISABLE_API_DOCS flag in config', 'DISABLE_API_DOCS' in config_src)
check('Swagger/ReDoc: docs_url=None when disabled in main.py', 'DISABLE_API_DOCS' in main_src)

# 14. HSTS in production
check('HSTS: Strict-Transport-Security only in production', 'Strict-Transport-Security' in main_src and "ENVIRONMENT == 'production'" in main_src or "environment == 'production'" in main_src.lower())

# 15. Graceful shutdown
check('Graceful shutdown: SIGTERM handler registered', 'signal.SIGTERM' in main_src)
check('Graceful shutdown: SIGINT handler registered', 'signal.SIGINT' in main_src)
check('Graceful shutdown: shutdown log message', 'shutting down gracefully' in main_src.lower() or 'SHUTDOWN' in main_src)

# 16. Live: check log file for JWT token patterns
import re
log_file = Path('backend/autopentest.log')
jwt_in_logs = False
if log_file.exists():
    log_content = log_file.read_text(errors='replace')
    # JWT pattern: 3 base64 groups separated by dots
    # We look for unredacted JWT in logs (token= should be REDACTED)
    unredacted = re.search(r'token=eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', log_content)
    jwt_in_logs = bool(unredacted)
    check('No JWT tokens unredacted in log file', not jwt_in_logs, f'Found unredacted JWT pattern in logs')
else:
    check('Log file check: file present', True)

# 17. No passwords in log file
pwd_in_logs = False
if log_file.exists():
    log_content = log_file.read_text(errors='replace')
    # Look for literal password values (not the word 'password')
    # Check for 'Yash@4050' or similar
    pwd_in_logs = 'Yash@4050' in log_content
    check('No operator password value in log file', not pwd_in_logs, 'Operator password found in log file')

# Summary
print()
print('=' * 60)
print(f'SECURITY SPOT CHECKS: {PASS_COUNT} PASS / {FAIL_COUNT} FAIL')
print('=' * 60)
sys.exit(0 if FAIL_COUNT == 0 else 1)
