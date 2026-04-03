import { useEffect, useState } from "react";

import { api } from "../api/client";

function UserTable({ users, onEdit, onDelete, onToggleAdmin }) {
  const [sortBy, setSortBy] = useState("created_at");
  const [sortOrder, setSortOrder] = useState("desc");
  const [filterRole, setFilterRole] = useState("");

  const filteredUsers = filterRole ? users.filter((u) => u.role === filterRole) : users;

  const sortedUsers = [...filteredUsers].sort((a, b) => {
    let aVal = a[sortBy];
    let bVal = b[sortBy];

    if (sortBy === "created_at") {
      aVal = new Date(aVal);
      bVal = new Date(bVal);
    }

    if (sortOrder === "asc") {
      return aVal > bVal ? 1 : -1;
    }
    return aVal < bVal ? 1 : -1;
  });

  const toggleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortOrder("asc");
    }
  };

  return (
    <div>
      <div style={{ marginBottom: "1rem", display: "flex", gap: "1rem" }}>
        <label>
          Filter by role:
          <select value={filterRole} onChange={(e) => setFilterRole(e.target.value)} style={{ marginLeft: "0.5rem", padding: "0.5rem" }}>
            <option value="">All roles</option>
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
        </label>
      </div>

      <div style={{ overflowX: "auto" }}>
        <table className="data-table" style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "2px solid #ddd" }}>
              <th style={{ padding: "1rem", textAlign: "left", cursor: "pointer" }} onClick={() => toggleSort("email")}>
                Email {sortBy === "email" && (sortOrder === "asc" ? "↑" : "↓")}
              </th>
              <th style={{ padding: "1rem", textAlign: "left", cursor: "pointer" }} onClick={() => toggleSort("role")}>
                Role {sortBy === "role" && (sortOrder === "asc" ? "↑" : "↓")}
              </th>
              <th style={{ padding: "1rem", textAlign: "left", cursor: "pointer" }} onClick={() => toggleSort("created_at")}>
                Created {sortBy === "created_at" && (sortOrder === "asc" ? "↑" : "↓")}
              </th>
              <th style={{ padding: "1rem", textAlign: "left" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {sortedUsers.map((user) => (
              <tr key={user.id} style={{ borderBottom: "1px solid #eee" }}>
                <td style={{ padding: "1rem" }}>{user.email}</td>
                <td style={{ padding: "1rem" }}>
                  <span
                    style={{
                      display: "inline-block",
                      padding: "0.25rem 0.75rem",
                      borderRadius: "4px",
                      background: user.role === "admin" ? "#ffe0e0" : "#e0f0ff",
                      color: user.role === "admin" ? "#d00" : "#006",
                      fontSize: "0.875rem",
                      fontWeight: "500",
                    }}
                  >
                    {user.role}
                  </span>
                </td>
                <td style={{ padding: "1rem" }}>{new Date(user.created_at).toLocaleDateString()}</td>
                <td style={{ padding: "1rem" }}>
                  <div style={{ display: "flex", gap: "0.5rem" }}>
                    <button
                      onClick={() => onToggleAdmin(user)}
                      style={{
                        padding: "0.5rem 1rem",
                        fontSize: "0.875rem",
                        background: user.role === "admin" ? "#fff3cd" : "#d4edda",
                        border: "1px solid #ddd",
                        borderRadius: "4px",
                        cursor: "pointer",
                      }}
                    >
                      {user.role === "admin" ? "Revoke Admin" : "Grant Admin"}
                    </button>
                    <button
                      onClick={() => onEdit(user)}
                      style={{
                        padding: "0.5rem 1rem",
                        fontSize: "0.875rem",
                        background: "#e3f2fd",
                        border: "1px solid #90caf9",
                        borderRadius: "4px",
                        cursor: "pointer",
                      }}
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => onDelete(user)}
                      style={{
                        padding: "0.5rem 1rem",
                        fontSize: "0.875rem",
                        background: "#ffebee",
                        border: "1px solid #ef5350",
                        color: "#c62828",
                        borderRadius: "4px",
                        cursor: "pointer",
                      }}
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function UserForm({ initialUser = null, onSubmit, onCancel }) {
  const [formData, setFormData] = useState({
    email: initialUser?.email || "",
    password: "",
    role: initialUser?.role || "user",
  });
  const [errors, setErrors] = useState({});

  function validate() {
    const newErrors = {};
    if (!formData.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = "Valid email is required";
    }
    if (!initialUser && (!formData.password || formData.password.length < 8)) {
      newErrors.password = "Password is required and must be at least 8 characters";
    }
    if (!["user", "admin"].includes(formData.role)) {
      newErrors.role = "Role must be 'user' or 'admin'";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  }

  function handleSubmit(e) {
    e.preventDefault();
    if (validate()) {
      onSubmit(formData);
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: "grid", gap: "1rem", maxWidth: "500px" }}>
      <div>
        <label style={{ display: "block", marginBottom: "0.5rem" }}>
          Email {errors.email && <span style={{ color: "#d00" }}>*</span>}
        </label>
        <input
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          placeholder="user@example.com"
          style={{
            width: "100%",
            padding: "0.75rem",
            border: errors.email ? "2px solid #d00" : "1px solid #ddd",
            borderRadius: "4px",
          }}
        />
        {errors.email && <small style={{ color: "#d00" }}>{errors.email}</small>}
      </div>

      {!initialUser && (
        <div>
          <label style={{ display: "block", marginBottom: "0.5rem" }}>
            Password {errors.password && <span style={{ color: "#d00" }}>*</span>}
          </label>
          <input
            type="password"
            value={formData.password}
            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            placeholder="Minimum 8 characters"
            style={{
              width: "100%",
              padding: "0.75rem",
              border: errors.password ? "2px solid #d00" : "1px solid #ddd",
              borderRadius: "4px",
            }}
          />
          {errors.password && <small style={{ color: "#d00" }}>{errors.password}</small>}
        </div>
      )}

      <div>
        <label style={{ display: "block", marginBottom: "0.5rem" }}>Role</label>
        <select
          value={formData.role}
          onChange={(e) => setFormData({ ...formData, role: e.target.value })}
          style={{
            width: "100%",
            padding: "0.75rem",
            border: "1px solid #ddd",
            borderRadius: "4px",
          }}
        >
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </div>

      <div style={{ display: "flex", gap: "1rem" }}>
        <button type="submit" className="primary-button" style={{ padding: "0.75rem 2rem" }}>
          {initialUser ? "Update User" : "Create User"}
        </button>
        <button type="button" onClick={onCancel} className="ghost-button" style={{ padding: "0.75rem 2rem" }}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function ConfirmDialog({ title, message, onConfirm, onCancel }) {
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0, 0, 0, 0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
      <div style={{ background: "white", padding: "2rem", borderRadius: "8px", maxWidth: "400px", boxShadow: "0 4px 12px rgba(0,0,0,0.15)" }}>
        <h2 style={{ marginBottom: "1rem" }}>{title}</h2>
        <p style={{ marginBottom: "2rem", color: "#666" }}>{message}</p>
        <div style={{ display: "flex", gap: "1rem" }}>
          <button onClick={onConfirm} style={{ padding: "0.75rem 2rem", background: "#d00", color: "white", border: "none", borderRadius: "4px", cursor: "pointer" }}>
            Confirm
          </button>
          <button onClick={onCancel} style={{ padding: "0.75rem 2rem", background: "#ddd", border: "none", borderRadius: "4px", cursor: "pointer" }}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

export default function UserManagement() {
  const [users, setUsers] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [confirmDialog, setConfirmDialog] = useState(null);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(true);

  async function loadUsers() {
    try {
      const { data } = await api.get("/admin/users?limit=1000");
      setUsers(data);
      setError("");
      setLoading(false);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load users");
      setLoading(false);
    }
  }

  useEffect(() => {
    loadUsers();
  }, []);

  async function handleCreateUser(formData) {
    try {
      await api.post("/admin/users", formData);
      setSuccess("User created successfully");
      setShowForm(false);
      await loadUsers();
      setTimeout(() => setSuccess(""), 3000);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to create user");
    }
  }

  async function handleUpdateUser(formData) {
    try {
      await api.put(`/admin/users/${editingUser.id}`, formData);
      setSuccess("User updated successfully");
      setEditingUser(null);
      await loadUsers();
      setTimeout(() => setSuccess(""), 3000);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to update user");
    }
  }

  async function handleDeleteUser(user) {
    try {
      await api.delete(`/admin/users/${user.id}`);
      setSuccess("User deleted successfully");
      setConfirmDialog(null);
      await loadUsers();
      setTimeout(() => setSuccess(""), 3000);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to delete user");
    }
  }

  async function handleToggleAdmin(user) {
    const newRole = user.role === "admin" ? "user" : "admin";
    try {
      await api.put(`/admin/users/${user.id}`, { role: newRole });
      setSuccess(`User role updated to ${newRole}`);
      await loadUsers();
      setTimeout(() => setSuccess(""), 3000);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to update user");
    }
  }

  if (loading) {
    return <div className="panel-card">Loading users...</div>;
  }

  return (
    <section className="panel-card">
      <h2>User Management</h2>

      {error && <div style={{ padding: "1rem", marginBottom: "1rem", background: "#fee", borderLeft: "4px solid #f00", color: "#d00" }}>{error}</div>}
      {success && <div style={{ padding: "1rem", marginBottom: "1rem", background: "#efe", borderLeft: "4px solid #0a0", color: "#0a0" }}>{success}</div>}

      {!showForm && !editingUser && (
        <button
          onClick={() => setShowForm(true)}
          className="primary-button"
          style={{ marginBottom: "2rem", padding: "0.75rem 1.5rem" }}
        >
          + Create New User
        </button>
      )}

      {showForm && (
        <div style={{ marginBottom: "2rem", padding: "1.5rem", background: "#f9f9f9", borderRadius: "4px", borderLeft: "4px solid #0066cc" }}>
          <h3>Create New User</h3>
          <UserForm
            onSubmit={handleCreateUser}
            onCancel={() => {
              setShowForm(false);
              setError("");
            }}
          />
        </div>
      )}

      {editingUser && (
        <div style={{ marginBottom: "2rem", padding: "1.5rem", background: "#f9f9f9", borderRadius: "4px", borderLeft: "4px solid #FF9800" }}>
          <h3>Edit User</h3>
          <UserForm
            initialUser={editingUser}
            onSubmit={handleUpdateUser}
            onCancel={() => {
              setEditingUser(null);
              setError("");
            }}
          />
        </div>
      )}

      <UserTable users={users} onEdit={setEditingUser} onDelete={(user) => setConfirmDialog(user)} onToggleAdmin={handleToggleAdmin} />

      {confirmDialog && (
        <ConfirmDialog
          title="Delete User?"
          message={`Are you sure you want to delete ${confirmDialog.email}? This action cannot be undone and will cascade delete all associated data.`}
          onConfirm={() => handleDeleteUser(confirmDialog)}
          onCancel={() => setConfirmDialog(null)}
        />
      )}
    </section>
  );
}
