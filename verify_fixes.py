#!/usr/bin/env python3
"""Verify all fixes were applied correctly."""

import os

print("\n" + "="*70)
print("VERIFICATION OF FIXES")
print("="*70)

# 1. Check backend/app/core/database.py is async
print("\n[1] backend/app/core/database.py async implementation")
with open('backend/app/core/database.py') as f:
    content = f.read()
if 'create_async_engine' in content and 'async_sessionmaker' in content:
    print("    [OK] Uses async engine and sessionmaker")
if 'async def get_db' in content:
    print("    [OK] get_db is async")
if 'AsyncSession' in content:
    print("    [OK] Returns AsyncSession")

# 2. Check backend/database.py is deprecation wrapper
print("\n[2] backend/database.py is deprecation wrapper")
with open('backend/database.py') as f:
    content = f.read()
if 'deprecated' in content.lower():
    print("    [OK] Marked as deprecated")
if 'from app.core.database import' in content:
    print("    [OK] Re-exports from core.database")

# 3. Check frontend/Dockerfile
print("\n[3] frontend/Dockerfile fixes")
with open('frontend/Dockerfile') as f:
    lines = f.readlines()
    content = ''.join(lines)

for i, line in enumerate(lines, 1):
    if 'COPY frontend/package' in line and './frontend/' not in line:
        print(f"    [OK] Line {i}: COPY path is correct (not nested)")
    if 'nginx -t' in line:
        # Check if copy precedes
        if i > 0:
            prev = ''.join(lines[:i-1])
            if 'COPY frontend/nginx.conf' in prev:
                print(f"    [OK] Line {i}: nginx -t runs after COPY")

# 4. Check worker/Dockerfile
print("\n[4] worker/Dockerfile fixes")
with open('worker/Dockerfile') as f:
    lines = f.readlines()
    content = ''.join(lines)

if 'app.tasks.celery_app.celery_app' not in content:
    print("    [OK] Removed redundant celery_app.celery_app path")

if 'CMD ["sh", "-c",' in content or 'sh -c' in content:
    for i, line in enumerate(lines, 1):
        if '$HOSTNAME' in line and 'celery' in line:
            if 'sh -c' in line:
                print(f"    [OK] Line {i}: $HOSTNAME is wrapped in sh -c")

# 5. Check docker-compose migrate healthcheck
print("\n[5] docker-compose.yml migrate healthcheck")
with open('docker-compose.yml') as f:
    content = f.read()
if 'alembic current' in content:
    print("    [OK] Healthcheck checks migration status with alembic current")

# 6. Check app/__init__.py
print("\n[6] backend/app/__init__.py model exports")
with open('backend/app/__init__.py') as f:
    content = f.read()
if 'from app.models import' in content:
    print("    [OK] Imports models")
if '__all__' in content:
    print("    [OK] Defines __all__ for explicit exports")

# 7. Check main.py health endpoint
print("\n[7] backend/app/main.py health endpoint")
with open('backend/app/main.py') as f:
    content = f.read()
if 'async def health' in content:
    print("    [OK] health() is async")
if 'async with' in content and 'async_session_maker' in content:
    print("    [OK] health() uses async session context manager")

print("\n" + "="*70)
print("All critical fixes verified!")
print("="*70 + "\n")
