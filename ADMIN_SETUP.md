# Admin Interface - Setup Guide

This guide provides step-by-step instructions for setting up and deploying the admin interface for ReconX Elite.

## Prerequisites

- ReconX Elite backend running on FastAPI
- ReconX Elite frontend set up with React/Vite
- PostgreSQL database configured
- Redis server running
- Celery worker process running

## Step 1: Create the Initial Admin User

Since authentication requires at least one admin user, you must create the first admin manually.

### Option A: Using Python Shell (Recommended)

```bash
cd backend
python -c "
from app.core.database import get_sessionmaker
from app.models.user import User
from app.core.security import hash_password

SessionLocal = get_sessionmaker()
db = SessionLocal()
admin = User(
    email='admin@example.com',
    password_hash=hash_password('your_secure_password'),
    role='admin'
)
db.add(admin)
db.commit()
print(f'✓ Admin user created: {admin.email} (ID: {admin.id})')
db.close()
"
```

### Option B: Using SQL Directly

```bash
# Connect to PostgreSQL
psql -U reconx -d reconx -h localhost

# Then paste this SQL:
INSERT INTO users (email, password_hash, role)
VALUES (
  'admin@example.com',
  -- Generate bcrypt hash using: from passlib.context import CryptContext; CryptContext(schemes=["bcrypt"]).hash("password")
  '$2b$12$...',
  'admin'
);

-- Verify admin was created:
SELECT id, email, role FROM users WHERE role = 'admin';
```

### Option C: Using Database GUI

If you have pgAdmin or similar tool:

1. Connect to the database
2. Open the `users` table
3. Insert a new row with:
   - `email`: admin@example.com
   - `password_hash`: (generate bcrypt hash)
   - `role`: admin

## Step 2: Verify Backend Admin Router

### Check that admin.py router exists

```bash
ls backend/app/routers/admin.py
```

### Verify router is included in main.py

```bash
grep "admin" backend/app/main.py
```

### Test admin endpoint (after starting services)

```bash
# Get access token via login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"your_password"}'

# Use token to test admin endpoint
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8000/admin/users
```

## Step 3: Verify Frontend Components

### Check that all files exist

```bash
ls frontend/src/pages/AdminDashboardPage.jsx
ls frontend/src/components/UserManagement.jsx
ls frontend/src/components/SystemHealth.jsx
ls frontend/src/components/ConfigurationManager.jsx
ls frontend/src/utils/jwt.js
```

### Verify App.jsx has admin route

```bash
grep "AdminRoute\|/admin" frontend/src/App.jsx
```

## Step 4: Start Services

### Terminal 1: Backend API

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Terminal 2: Celery Worker

```bash
cd backend
source .venv/bin/activate
celery -A app.tasks.celery_app.celery_app worker --loglevel=info
```

### Terminal 3: Frontend

```bash
cd frontend
npm install
npm run dev
```

## Step 5: Access Admin Interface

1. **Open browser**: `http://localhost:5173`
2. **Log in** with admin credentials:
   - Email: `admin@example.com`
   - Password: (the password you set)
3. **Click "Admin Panel"** button in top right (visible only to admins)
4. **Explore admin features**:
   - Overview tab for quick stats
   - Users tab to manage accounts
   - System Health tab to monitor services
   - Configuration tab to adjust settings

## Step 6: Create Additional Admin Users (Optional)

Once you have access to the admin panel:

1. Navigate to the **Users** tab
2. Click **"+ Create New User"**
3. Enter details:
   - Email: (unique email address)
   - Password: (minimum 8 characters)
   - Role: Select "Admin"
4. Click **"Create User"**

The new admin can now log in and access `/admin`.

## Deployment to Docker

If deploying with Docker Compose:

### 1. Before First Start

Create migration to ensure schema:

```bash
docker compose run backend alembic upgrade head
```

Create admin user via Python in container:

```bash
docker compose run backend python -c "
from app.core.database import get_sessionmaker
from app.models.user import User
from app.core.security import hash_password

SessionLocal = get_sessionmaker()
db = SessionLocal()
admin = User(
    email='admin@example.com',
    password_hash=hash_password('secure_password'),
    role='admin'
)
db.add(admin)
db.commit()
print('Admin created')
db.close()
"
```

### 2. Start Services

```bash
docker compose up -d
```

### 3. Access Admin Panel

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000` (or your deployment domain)

## Troubleshooting

### Problem: "Admin role required" when accessing /admin

**Solution:**

- Verify user's role is "admin" in database:
  ```sql
  SELECT email, role FROM users WHERE email = 'admin@example.com';
  ```
- If role is "user", update it:
  ```sql
  UPDATE users SET role = 'admin' WHERE email = 'admin@example.com';
  ```

### Problem: Admin panel button doesn't appear

**Solution:**

- Clear browser cache (`Ctrl+Shift+Del`)
- Check that AuthContext is correctly decoding JWT
- Verify access token has role in payload:
  ```javascript
  // In browser console:
  JSON.parse(atob(localStorage.getItem("reconx_auth").split(".")[1]));
  ```

### Problem: System Health shows "unhealthy" for services

**Solution:**

- **PostgreSQL**: Check connection string in `.env`
- **Redis**: Start Redis server: `redis-server`
- **Celery**: Start worker process in separate terminal

### Problem: Configuration changes don't persist after restart

**Expected behavior** - Changes are in-memory only. To make permanent:

1. Update `.env` file with new values
2. Restart application

### Problem: "Failed to create user" error

**Check**:

- Email is unique (not already registered)
- Password is at least 8 characters
- Check server logs for detailed error

## Security Checklist

- [ ] Changed default admin password to something strong
- [ ] Limited admin accounts to necessary personnel only
- [ ] Enabled HTTPS in production (set CORS_ALLOWED_ORIGINS)
- [ ] Set secure JWT_SECRET_KEY (not "change-me-in-production")
- [ ] Configured DATABASE_URL to use strong credentials
- [ ] Set REDIS_URL to secure connection
- [ ] Reviewed audit logs regularly
- [ ] Tested that non-admin users cannot access /admin

## Next Steps

- Review [ADMIN_INTERFACE.md](./ADMIN_INTERFACE.md) for detailed feature documentation
- Set up automated backups for the database
- Configure monitoring/alerting for system health
- Create additional admin accounts as needed
- Test user management workflows
- Document any custom configuration changes

## Support

For issues or questions:

1. Check [ADMIN_INTERFACE.md](./ADMIN_INTERFACE.md) troubleshooting section
2. Review server logs: `docker compose logs backend`
3. Check worker logs: `docker compose logs worker`
4. Verify database connectivity
5. Check Redis connectivity
