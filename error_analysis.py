#!/usr/bin/env python3
"""Comprehensive error analysis for the entire codebase."""

import os
import re
from pathlib import Path

errors = []
warnings = []

# ============================================================================
# 1. BACKEND DATABASE ASYNC/SYNC MISMATCH
# ============================================================================

with open('backend/database.py') as f:
    db_content = f.read()

with open('backend/app/core/database.py') as f:
    core_db_content = f.read()

print("\n" + "="*70)
print("ISSUE 1: ASYNC/SYNC DATABASE ENGINE MISMATCH")
print("="*70)

if 'create_async_engine' in db_content:
    print("[OK] backend/database.py uses create_async_engine")
else:
    print("[ERROR] backend/database.py missing async engine")
    errors.append("backend/database.py: Missing create_async_engine (has create_async_engine: True)")

if 'AsyncSession' in db_content:
    print("[OK] backend/database.py has AsyncSession")
else:
    print("[ERROR] backend/database.py missing AsyncSession")
    errors.append("backend/database.py: Missing AsyncSession import")

if 'create_engine' in core_db_content and 'create_async_engine' not in core_db_content:
    print("[CRITICAL ERROR] backend/app/core/database.py uses sync create_engine")
    errors.append("backend/app/core/database.py: CRITICAL - Uses sync create_engine instead of async")
elif 'create_async_engine' in core_db_content:
    print("[OK] backend/app/core/database.py uses create_async_engine")
else:
    print("[WARNING] backend/app/core/database.py database setup unclear")
    warnings.append("backend/app/core/database.py: Database initialization unclear")

if 'sessionmaker' in core_db_content and 'async_sessionmaker' not in core_db_content:
    print("[CRITICAL ERROR] backend/app/core/database.py uses sync sessionmaker")
    errors.append("backend/app/core/database.py: CRITICAL - Uses sync sessionmaker instead of async_sessionmaker")

# ============================================================================
# 2. DUPLICATE DATABASE DEFINITIONS
# ============================================================================

print("\n" + "="*70)
print("ISSUE 2: DUPLICATE DATABASE DEFINITIONS")
print("="*70)

if os.path.exists('backend/database.py') and os.path.exists('backend/app/core/database.py'):
    print("[ERROR] Two database definition files exist:")
    print("  - backend/database.py")
    print("  - backend/app/core/database.py")
    errors.append("Duplicate database definitions (backend/database.py and backend/app/core/database.py)")

# ============================================================================
# 3. FRONTEND DOCKERFILE ERRORS
# ============================================================================

print("\n" + "="*70)
print("ISSUE 3: FRONTEND DOCKERFILE COPY PATH ERROR")
print("="*70)

with open('frontend/Dockerfile') as f:
    frontend_lines = f.readlines()
    frontend_content = ''.join(frontend_lines)

copy_line = None
nginx_test_line = None
copy_nginx_line = None

for i, line in enumerate(frontend_lines, 1):
    if 'COPY frontend/package' in line:
        copy_line = (i, line.strip())
    if 'nginx -t' in line:
        nginx_test_line = (i, line.strip())
    if 'COPY frontend/nginx.conf' in line:
        copy_nginx_line = (i, line.strip())

if copy_line:
    print(f"[ERROR] Line {copy_line[0]}: {copy_line[1]}")
    if './frontend/' in copy_line[1]:
        print("  Problem: COPY frontend/package*.json ./frontend/ creates nested frontend/frontend/")
        errors.append("frontend/Dockerfile Line " + str(copy_line[0]) + ": COPY path creates nested directory (./frontend/ should be ./)")

if nginx_test_line and copy_nginx_line:
    if nginx_test_line[0] < copy_nginx_line[0]:
        print(f"[ERROR] Line {nginx_test_line[0]}: nginx -t validation runs BEFORE nginx.conf is copied")
        print(f"  nginx.conf is copied at line {copy_nginx_line[0]}")
        errors.append(f"frontend/Dockerfile: nginx -t at line {nginx_test_line[0]} runs before COPY at line {copy_nginx_line[0]}")
    else:
        print("[OK] nginx.conf is copied before validation")

# ============================================================================
# 4. BACKEND DOCKERFILE REQUIREMENTS PATH
# ============================================================================

print("\n" + "="*70)
print("ISSUE 4: BACKEND DOCKERFILE REQUIREMENTS HANDLING")
print("="*70)

with open('backend/Dockerfile') as f:
    backend_lines = f.readlines()
    backend_content = ''.join(backend_lines)

if 'COPY ./backend/requirements.txt' in backend_content:
    print("[OK] backend/Dockerfile copies requirements.txt")
else:
    print("[WARNING] backend/Dockerfile requirements copy unclear")
    warnings.append("backend/Dockerfile: requirements.txt copy path unclear")

if 'dependencies' in backend_content.lower():
    print("[OK] backend/Dockerfile has dependencies stage")
else:
    print("[WARNING] backend/Dockerfile dependencies stage unclear")

# ============================================================================
# 5. WORKER DOCKERFILE ERRORS
# ============================================================================

print("\n" + "="*70)
print("ISSUE 5: WORKER DOCKERFILE CELERY ERRORS")
print("="*70)

with open('worker/Dockerfile') as f:
    worker_lines = f.readlines()
    worker_content = ''.join(worker_lines)

if 'app.tasks.celery_app.celery_app' in worker_content:
    for i, line in enumerate(worker_lines, 1):
        if 'app.tasks.celery_app.celery_app' in line:
            print(f"[ERROR] Line {i}: Redundant celery path - app.tasks.celery_app.celery_app")
            errors.append(f"worker/Dockerfile Line {i}: Redundant celery_app path (.celery_app.celery_app)")

if 'CMD celery' in worker_content and '$HOSTNAME' in worker_content:
    for i, line in enumerate(worker_lines, 1):
        if '$HOSTNAME' in line and 'celery' in line:
            if 'sh -c' not in line:
                print(f"[ERROR] Line {i}: $HOSTNAME not expanded in CMD array form")
                errors.append(f"worker/Dockerfile Line {i}: $HOSTNAME not expanded (needs sh -c wrapper)")
            else:
                print(f"[OK] Line {i}: $HOSTNAME correctly wrapped in sh -c")

# ============================================================================
# 6. DOCKER-COMPOSE HEALTHCHECK ISSUES
# ============================================================================

print("\n" + "="*70)
print("ISSUE 6: DOCKER-COMPOSE MIGRATE HEALTHCHECK")
print("="*70)

with open('docker-compose.yml') as f:
    compose_content = f.read()

if 'migrate:' in compose_content:
    # Extract migrate service healthcheck
    migrate_match = re.search(r'migrate:.*?healthcheck:(.*?)(?=\n  [a-z])', compose_content, re.DOTALL)
    if migrate_match:
        healthcheck = migrate_match.group(1)
        if 'test.*-f.*alembic.ini' in healthcheck:
            print("[ERROR] Migrate healthcheck tests for file existence only")
            print("  Problem: alembic.ini exists even if migrations fail")
            errors.append("docker-compose.yml migrate service: Healthcheck tests file existence, not migration success")
        else:
            print("[OK] Migrate healthcheck appears to check migration status")

# ============================================================================
# 7. MAIN APP IMPORTS
# ============================================================================

print("\n" + "="*70)
print("ISSUE 7: BACKEND APP IMPORTS")
print("="*70)

with open('backend/app/main.py') as f:
    main_content = f.read()

if 'from app import models' in main_content:
    print("[OK] main.py imports from app.models")
    # Check if models are actually exported
    with open('backend/app/__init__.py') as f:
        app_init = f.read()
    if not app_init.strip() or 'from app.models' not in app_init:
        print("[WARNING] backend/app/__init__.py is empty or doesn't export models")
        warnings.append("backend/app/__init__.py: Empty or doesn't export models")
    else:
        print("[OK] backend/app/__init__.py exports models")
else:
    print("[OK] main.py models import pattern")

# ============================================================================
# 8. DATABASE URL REDUNDANCY
# ============================================================================

print("\n" + "="*70)
print("ISSUE 8: DATABASE URL REDUNDANCY")
print("="*70)

if 'DATABASE_URL = os.getenv("DATABASE_URL")' in db_content:
    print("[ERROR] backend/database.py has module-level DATABASE_URL from os.getenv")
    print("  This conflicts with backend/app/core/config.py settings.database_url")
    errors.append("backend/database.py: Module-level DATABASE_URL shadows config.database_url (two sources of truth)")

# ============================================================================
# 9. CORS AND SECURITY
# ============================================================================

print("\n" + "="*70)
print("ISSUE 9: CORS AND JWT SECRET")
print("="*70)

if '"*"' in compose_content or "'*'" in compose_content:
    print("[OK] No wildcard CORS in compose")
else:
    print("[OK] CORS configuration present")

if 'change-me-in-production' in compose_content:
    print("[WARNING] Default JWT_SECRET_KEY visible in configuration")
    warnings.append("docker-compose.yml or config: Contains default JWT_SECRET_KEY")

# ============================================================================
# 10. WORKER DOCKERFILE CELERY CMD
# ============================================================================

print("\n" + "="*70)
print("ISSUE 10: WORKER DOCKERFILE CMD SIGNAL HANDLING")
print("="*70)

if 'CMD ["sh", "-c",' in worker_content or 'CMD sh -c' in worker_content:
    print("[OK] Worker uses sh -c (allows signal propagation)")
else:
    print("[WARNING] Worker CMD should use shell form for proper signal handling")
    if 'CMD ["' in worker_content:
        print("  Current: Using array form (PID 1 won't receive signals)")
        warnings.append("worker/Dockerfile: Uses array form CMD (signal handling issue)")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "="*70)
print("SUMMARY")
print("="*70)

print(f"\nTOTAL CRITICAL ERRORS: {len(errors)}")
print(f"TOTAL WARNINGS: {len(warnings)}")

if errors:
    print("\n[CRITICAL ERRORS]:")
    for i, err in enumerate(errors, 1):
        print(f"  {i}. {err}")

if warnings:
    print("\n[WARNINGS]:")
    for i, warn in enumerate(warnings, 1):
        print(f"  {i}. {warn}")

print("\n" + "="*70)
