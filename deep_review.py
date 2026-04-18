#!/usr/bin/env python3
"""Deep code review: Find runtime bugs, logic errors, security issues."""

import os
import re
from pathlib import Path

issues = []

print("\n" + "="*80)
print("DEEP CODE REVIEW: RUNTIME BUGS & LOGIC ERRORS")
print("="*80)

# ============================================================================
# 1. CHECK ROUTER FILES FOR COMMON ISSUES
# ============================================================================

print("\n[CHECKING] Router files for missing error handling...")

router_files = [
    'backend/app/routers/auth.py',
    'backend/app/routers/scans.py',
    'backend/app/routers/targets.py',
    'backend/app/routers/vulnerabilities.py',
]

for router_file in router_files:
    if not os.path.exists(router_file):
        print(f"  [SKIP] {router_file} not found")
        continue
    
    with open(router_file) as f:
        content = f.read()
    
    # Check for proper exception handling
    if '@router' in content:
        if 'try:' not in content and 'HTTPException' not in content:
            print(f"  [WARN] {router_file}: May lack exception handling")
            issues.append(f"{router_file}: Missing exception handling in endpoints")

# ============================================================================
# 2. CHECK DATABASE QUERIES FOR SQL INJECTION / N+1 PROBLEMS
# ============================================================================

print("\n[CHECKING] Database queries for vulnerabilities...")

db_files = [
    'backend/app/db',
    'backend/app/services',
]

for db_dir in db_files:
    if not os.path.exists(db_dir):
        continue
    
    for root, dirs, files in os.walk(db_dir):
        for file in files:
            if not file.endswith('.py'):
                continue
            
            filepath = os.path.join(root, file)
            with open(filepath) as f:
                content = f.read()
            
            # Check for raw string queries
            if re.search(r'query\s*=\s*["\'].*SELECT.*f["\']', content):
                print(f"  [DANGER] {filepath}: F-string in SQL query (SQL injection risk)")
                issues.append(f"{filepath}: F-string SQL queries (injection risk)")
            
            # Check for missing error handling on transactions
            if 'session.commit()' in content and 'except' not in content:
                print(f"  [WARN] {filepath}: commit() without error handling")
                issues.append(f"{filepath}: commit() not wrapped in try/except")

# ============================================================================
# 3. CHECK AUTHENTICATION / JWT HANDLING
# ============================================================================

print("\n[CHECKING] Authentication and JWT security...")

with open('backend/app/core/config.py') as f:
    config_content = f.read()

if 'jwt_secret_key: str = Field(default="change-me-in-production"' in config_content:
    print("  [CRITICAL] JWT_SECRET_KEY still has default value in code")
    issues.append("JWT_SECRET_KEY: Default value in source code")

if 'JWT_ALGORITHM' in config_content:
    if '"HS256"' in config_content or "'HS256'" in config_content:
        print("  [INFO] JWT using HS256 (symmetric, suitable for single service)")

# ============================================================================
# 4. CHECK FOR HARDCODED CREDENTIALS / SECRETS
# ============================================================================

print("\n[CHECKING] Hardcoded credentials...")

sensitive_patterns = [
    (r'password\s*=\s*["\'].*["\']', 'Hardcoded password'),
    (r'api_key\s*=\s*["\'].*["\']', 'Hardcoded API key'),
    (r'secret\s*=\s*["\'](?!change-me)["\']', 'Hardcoded secret'),
]

check_files = [
    'backend/app/core/config.py',
    'backend/app/main.py',
    'docker-compose.yml',
]

for check_file in check_files:
    if not os.path.exists(check_file):
        continue
    
    with open(check_file) as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines, 1):
        for pattern, desc in sensitive_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Exclude .env and example files
                if 'change-me' not in line and '.env' not in check_file:
                    print(f"  [WARN] {check_file}:{i}: Possible {desc}")
                    issues.append(f"{check_file}:{i}: {desc}")

# ============================================================================
# 5. CHECK ERROR HANDLING IN MAIN.PY
# ============================================================================

print("\n[CHECKING] Error handling in main.py...")

with open('backend/app/main.py') as f:
    main_content = f.read()

# Check if all exception handlers are registered
required_handlers = [
    ('HTTPException', 'http_exception_handler'),
    ('Exception', 'unhandled_exception_handler'),
]

for exc_name, handler_name in required_handlers:
    if f'add_exception_handler({exc_name}' not in main_content:
        print(f"  [WARN] Missing exception handler for {exc_name}")
        issues.append(f"main.py: Missing handler for {exc_name}")

# ============================================================================
# 6. CHECK DATABASE CONNECTION ISSUES
# ============================================================================

print("\n[CHECKING] Database connection handling...")

with open('backend/app/core/database.py') as f:
    db_content = f.read()

if 'pool_pre_ping=True' not in db_content:
    print("  [WARN] Database pool missing pre_ping (stale connections)")
    issues.append("database.py: Missing pool_pre_ping=True (can cause stale connections)")

if 'pool_recycle' not in db_content:
    print("  [WARN] Database pool missing recycle setting")
    issues.append("database.py: Missing pool_recycle (connections may become stale)")

# ============================================================================
# 7. CHECK ASYNC/AWAIT ISSUES
# ============================================================================

print("\n[CHECKING] Async/await consistency...")

with open('backend/app/main.py') as f:
    main_lines = f.readlines()

for i, line in enumerate(main_lines, 1):
    if 'def ' in line and '(' in line:
        func_signature = line.strip()
        # Find the body
        is_async = 'async def' in func_signature
        if 'await ' in ''.join(main_lines[i:i+10]):
            if not is_async:
                print(f"  [ERROR] main.py:{i}: await used in sync function {func_signature}")
                issues.append(f"main.py:{i}: await in non-async function")

# ============================================================================
# 8. CHECK DOCKER-COMPOSE FOR ISSUES
# ============================================================================

print("\n[CHECKING] docker-compose.yml...")

with open('docker-compose.yml') as f:
    compose_lines = f.readlines()

for i, line in enumerate(compose_lines, 1):
    # Check for missing environment variable defaults
    if '${' in line and ':-' not in line and ':}' not in line:
        if not line.strip().startswith('#'):
            print(f"  [WARN] docker-compose.yml:{i}: Variable without default: {line.strip()}")
            issues.append(f"docker-compose.yml:{i}: Variable ${'{...}'} missing default value")

# Check resource limits
if 'memory:' not in ''.join(compose_lines):
    print("  [WARN] docker-compose.yml: No memory limits set")
    issues.append("docker-compose.yml: Missing memory resource limits")

# ============================================================================
# 9. CHECK LOGGING CONFIGURATION
# ============================================================================

print("\n[CHECKING] Logging and debugging...")

if os.path.exists('backend/app/core/logging_config.py'):
    with open('backend/app/core/logging_config.py') as f:
        log_content = f.read()
    
    if 'level=logging.DEBUG' in log_content:
        print("  [WARN] Logging set to DEBUG level (verbose, may leak info)")
        issues.append("logging_config.py: DEBUG level enabled in config")
else:
    print("  [INFO] logging_config.py not found")

# ============================================================================
# 10. CHECK API RATE LIMITING
# ============================================================================

print("\n[CHECKING] Rate limiting configuration...")

with open('backend/app/core/config.py') as f:
    config_lines = f.readlines()

rate_limits_found = []
for line in config_lines:
    if '_rate_limit' in line:
        rate_limits_found.append(line.strip())

if not rate_limits_found:
    print("  [WARN] No rate limits configured")
    issues.append("config.py: No rate limiting configured")
else:
    print(f"  [OK] Rate limits configured: {len(rate_limits_found)} entries")

# ============================================================================
# 11. CHECK FOR MISSING INPUT VALIDATION
# ============================================================================

print("\n[CHECKING] Input validation in endpoints...")

if os.path.exists('backend/app/routers/scans.py'):
    with open('backend/app/routers/scans.py') as f:
        scan_content = f.read()
    
    # Check for Pydantic validators
    if 'field_validator' not in scan_content and 'validator' not in scan_content:
        print("  [WARN] scans.py: May lack Pydantic validators")
        issues.append("scans.py: Missing Pydantic field validators")

# ============================================================================
# 12. CHECK FOR DEPENDENCY VULNERABILITIES
# ============================================================================

print("\n[CHECKING] Dependencies...")

with open('backend/requirements.txt') as f:
    requirements = f.read()

# Known vulnerable packages
vulnerable_packages = {
    'requests': '2.31.0',  # Before this had CVEs
}

for package, min_version in vulnerable_packages.items():
    if package in requirements:
        print(f"  [INFO] {package} installed (check version in requirements.txt)")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "="*80)
print(f"TOTAL ISSUES FOUND: {len(issues)}")
print("="*80)

if issues:
    print("\nISSUES:")
    for i, issue in enumerate(issues, 1):
        print(f"  {i}. {issue}")
else:
    print("\nNo major issues found!")

print("\n" + "="*80)
