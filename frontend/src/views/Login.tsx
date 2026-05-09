/**
 * Login.tsx — Username/password authentication form.
 *
 * Security:
 *   - On success, access token stored in module memory (not localStorage)
 *   - Refresh token is set as httpOnly cookie by the backend — JS never sees it
 *   - Error messages are generic — do not reflect backend error detail
 *   - Form is plain HTML — no third-party form library dependencies
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../api/client";
import { Database } from "lucide-react";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
      navigate("/");
    } catch {
      // Generic error — never reflect server-side detail to the client
      setError("Invalid username or password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-3 mb-8 justify-center">
          <Database size={28} className="text-primary" />
          <span className="text-xl font-bold">fried-plantains</span>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-card border border-border rounded-lg p-6 space-y-4"
        >
          <h1 className="text-lg font-semibold text-center">Sign in</h1>

          {error && (
            <div className="bg-destructive/20 border border-destructive/50 rounded p-3 text-sm text-destructive-foreground">
              {error}
            </div>
          )}

          <div className="space-y-1">
            <label className="text-sm text-muted-foreground">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-input border border-border rounded px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              autoComplete="username"
              required
            />
          </div>

          <div className="space-y-1">
            <label className="text-sm text-muted-foreground">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-input border border-border rounded px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              autoComplete="current-password"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-primary text-primary-foreground py-2 rounded text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
          >
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <p className="text-center text-xs text-muted-foreground mt-4">
          fried-plantains SIEM — homelab threat hunting platform
        </p>
      </div>
    </div>
  );
}
