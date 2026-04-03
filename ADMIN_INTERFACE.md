# ReconX Elite Admin Interface Documentation

## Overview

The ReconX Elite Admin Interface provides system administrators with tools to manage users, monitor system health, and configure application settings. Access is restricted to users with the `admin` role.

## Access & Authentication

### Accessing the Admin Panel

1. Log in with an admin account
2. Navigate to `http://localhost:5173/admin` (or your deployment URL)
3. You'll see an "Admin Panel" button in the top navigation of the dashboard (visible only to admins)

### Setting Up the First Admin User

Since the system requires at least one admin, you'll need to manually create the first admin user in the database:

```bash
# From the backend directory
# Option 1: Using the Python shell
python
>>> from app.core.database import get_sessionmaker
>>> from app.models.user import User
>>> from app.core.security import hash_password
>>>
>>> SessionLocal = get_sessionmaker()
>>> db = SessionLocal()
>>> admin_user = User(
...     email="admin@example.com",
...     password_hash=hash_password("secure_password_here"),
...     role="admin"
... )
>>> db.add(admin_user)
>>> db.commit()
>>> print(f"Admin user created with ID: {admin_user.id}")
```

Alternatively, you can create it directly via SQL:

```sql
INSERT INTO users (email, password_hash, role)
VALUES (
  'admin@example.com',
  '$2b$12$...',  -- bcrypt hash
  'admin'
);
```

## Admin Dashboard Features

### 1. Overview Tab

Quick access dashboard showing:

- Total users in the system
- Total targets registered
- Total scans performed
- Active scans running
- Queued tasks

Shortcuts to major admin functions:

- Manage Users
- System Health
- Configuration

### 2. Users Tab

#### User Management Features

**View All Users:**

- Displays a sortable, filterable table of all registered users
- Click column headers to sort by email, role, or creation date
- Filter by role (User or Admin)

**Create New User:**

1. Click "+ Create New User" button
2. Fill in:
   - Email address (unique)
   - Password (minimum 8 characters)
   - Role (User or Admin)
3. Click "Create User"

The new user will receive their credentials and can log in immediately.

**Edit User:**

1. Click "Edit" button on any user row
2. Update email address (optional) or role
3. Click "Update User"

**Toggle Admin Status:**

- Click "Grant Admin" or "Revoke Admin" button to quickly change a user's role
- Useful for promoting/demoting users without editing other details

**Delete User:**

1. Click "Delete" button
2. Confirm in the dialog
3. ⚠️ User deletion cascades and removes:
   - All targets owned by the user
   - All scans for those targets
   - All associated data (subdomains, endpoints, vulnerabilities, etc.)
   - This action cannot be undone

### 3. System Health Tab

Real-time monitoring of critical infrastructure:

**Service Status Indicators:**

- **PostgreSQL Database**: Connection and query execution status
- **Redis Cache**: Cache server availability for task queueing
- **Celery Worker**: Background task processing status
- **Overall Status**: Aggregated health (healthy/degraded/unhealthy)

**Features:**

- Auto-refreshes every 30 seconds
- Manual refresh button for immediate updates
- Displays timestamps of last update
- Recent audit logs showing administrative actions

**Interpreting Health Status:**

- ✓ **Healthy**: Service is operational and responsive
- ⚠ **Degraded**: Service has some issues but may still function
- ✕ **Unhealthy**: Service is down or unreachable
- **?** **Unknown**: Status cannot be determined

### 4. Configuration Tab

Manage application settings without restarting the server.

#### ⚠️ Important Notes

- **In-Memory Changes**: All configuration changes apply to the running application instance only
- **Not Persistent**: Changes will be **lost on application restart**
- **For Permanent Changes**: Update the `.env` file and restart the application
- **Recommended Workflow**: Test changes via this interface, then add to `.env` and restart

#### Configurable Settings

**Scan Configuration:**

- **Scan Throttle Seconds**: Cooldown between consecutive scans per user (prevents abuse)
- **Nuclei Target Cap**: Maximum URLs sent to nuclei scanner
- **Header Probe Cap**: Maximum URLs for HTTP header probing
- **Nuclei Templates Path**: Path to custom nuclei vulnerability templates

**Takeover Detection:**

- **CNAME Indicators**: Comma-separated list of DNS suffixes indicating potential subdomain takeovers
  - Examples: `amazonaws.com`, `azurewebsites.net`, `github.io`

**Security & CORS:**

- **CORS Allowed Origins**: Comma-separated list of domains allowed to access the API
  - Required for cross-origin requests from frontend
  - Multiple origins: `http://localhost:5173,https://app.example.com`

**Read-Only Settings:**

- Access Token Expiry (minutes)
- Refresh Token Expiry (minutes)
- JavaScript Asset Fetch Timeout (seconds)
- Maximum JavaScript Assets to fetch

These are configured via environment variables and cannot be changed at runtime.

## Audit Logging

All administrative actions are logged:

| Action                 | Details                          |
| ---------------------- | -------------------------------- |
| `admin_user_created`   | User email and assigned role     |
| `admin_user_updated`   | User ID, old role, new role      |
| `admin_user_deleted`   | Deleted user email               |
| `admin_config_updated` | Which config fields were changed |

View audit logs in the System Health tab to track admin activities.

## API Endpoints Reference

### User Management

- `GET /admin/users` - List all users
- `POST /admin/users` - Create new user
- `GET /admin/users/{user_id}` - Get user details
- `PUT /admin/users/{user_id}` - Update user
- `DELETE /admin/users/{user_id}` - Delete user

### System Monitoring

- `GET /admin/health` - System service status
- `GET /admin/metrics` - System metrics and statistics
- `GET /admin/audit-logs` - List audit log entries

### Configuration

- `GET /admin/config` - View current configuration
- `PUT /admin/config` - Update configuration (in-memory)

All endpoints require:

- Valid authentication token (Bearer JWT)
- User must have `role: "admin"`

## Security Best Practices

1. **Protect Admin Accounts**
   - Use strong passwords (16+ characters recommended)
   - Limit admin accounts to trusted personnel only
   - Monitor audit logs for suspicious activity

2. **Rate Limiting**
   - All operations are rate-limited by IP/user
   - Exceeding limits will return HTTP 429

3. **Audit Trail**
   - All admin actions are logged with IP address and timestamp
   - Review logs regularly for unauthorized access attempts

4. **Configuration Changes**
   - Test changes in development first
   - Document permanent changes in `.env`
   - Never commit sensitive values (keys, passwords) to version control

5. **User Deletion**
   - Verify before deleting users
   - Deletion cascades to all related data
   - Consider archiving instead of deleting for important accounts

## Troubleshooting

### "Admin role required" Error

- Ensure user account has `role: "admin"` in the database
- Check JWT token hasn't expired
- Clear browser cache and try logging out/in

### Health Check Shows Services Unhealthy

- **PostgreSQL**: Check database connection string in `.env`
- **Redis**: Verify Redis server is running and accessible
- **Celery**: Ensure Celery worker process is running
  ```bash
  celery -A app.tasks.celery_app.celery_app worker --loglevel=info
  ```

### Configuration Changes Not Saving

- Check browser console for API error messages
- Verify you have admin privileges
- Try refreshing the page and trying again

### Can't Create Admin User

- Ensure email is unique (not already registered)
- Verify password meets minimum length requirement (8 characters)
- Check server logs for detailed error messages

## Example Workflows

### Promote User to Admin

1. Go to Users tab
2. Find the user in the table
3. Click "Grant Admin" button
4. Confirm action
5. User can now access `/admin`

### Investigate System Performance Issues

1. Go to System Health tab
2. Check service status indicators
3. View recent audit logs
4. Click "Refresh" to get latest data
5. Check individual service status

### Temporarily Increase Scan Capacity

1. Go to Configuration tab
2. Increase "Nuclei Target Cap" value
3. Click "Save Configuration"
4. Changes apply immediately to new scans
5. ⚠️ Remember: Changes are lost on restart
6. For permanent changes, update `.env`

### Audit User Activity

1. Go to System Health tab
2. Scroll to "Recent Audit Logs" section
3. Filter by action type if needed
4. Review timestamps and IP addresses
5. Investigate suspicious patterns

## API Usage Examples

### Get All Users (cURL)

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8000/admin/users
```

### Create Admin User (Python)

```python
import requests

headers = {"Authorization": f"Bearer {access_token}"}
data = {
    "email": "newadmin@example.com",
    "password": "secure_password",
    "role": "admin"
}
response = requests.post("http://localhost:8000/admin/users", json=data, headers=headers)
print(response.json())
```

### Check System Health (JavaScript/Fetch)

```javascript
const response = await fetch("/admin/health", {
  headers: { Authorization: `Bearer ${accessToken}` },
});
const health = await response.json();
console.log(health);
```

## Performance Considerations

- User list pagination: First 100 users are returned; use `skip`/`limit` parameters for more
- Audit logs: Queries recent 100 logs by default
- Health checks: May take 2-3 seconds if services are slow
- Config updates: Changes apply immediately but only in-memory

## Related Documentation

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://react.dev/)
- [Celery Task Queue](https://docs.celeryproject.org/)
- [SQLAlchemy ORM](https://docs.sqlalchemy.org/)
