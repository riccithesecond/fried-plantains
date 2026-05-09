/**
 * Layout.tsx — App shell with dark sidebar navigation.
 *
 * SOC tooling is always dark — this component enforces dark mode globally.
 * The sidebar shows active alert count as a badge on the Alerts nav item.
 */

import {
  Activity,
  AlertTriangle,
  BarChart2,
  Database,
  LogOut,
  Search,
  Settings,
  Shield,
  Upload,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { listAlerts, logout } from "../api/client";

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
}

const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", path: "/", icon: <BarChart2 size={18} /> },
  { label: "Workbench", path: "/workbench", icon: <Search size={18} /> },
  { label: "Detections", path: "/detections", icon: <Shield size={18} /> },
  { label: "Alerts", path: "/alerts", icon: <AlertTriangle size={18} /> },
  { label: "Ingest", path: "/ingest", icon: <Upload size={18} /> },
  { label: "Settings", path: "/settings", icon: <Settings size={18} /> },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const [openAlertCount, setOpenAlertCount] = useState(0);

  useEffect(() => {
    listAlerts({ status: "open" })
      .then((alerts) => setOpenAlertCount(alerts.length))
      .catch(() => {}); // Non-critical — badge just won't show
  }, [location.pathname]);

  const handleLogout = async () => {
    await logout();
    window.location.href = "/login";
  };

  return (
    <div className="flex h-screen bg-background text-foreground overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 flex flex-col bg-card border-r border-border">
        {/* Logo */}
        <div className="flex items-center gap-2 px-4 py-4 border-b border-border">
          <Database size={20} className="text-primary" />
          <span className="font-bold text-sm tracking-wide">fried-plantains</span>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-4 space-y-1">
          {NAV_ITEMS.map((item) => {
            const isActive = location.pathname === item.path ||
              (item.path !== "/" && location.pathname.startsWith(item.path));
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? "bg-primary/20 text-primary"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted"
                }`}
              >
                {item.icon}
                <span className="flex-1">{item.label}</span>
                {item.label === "Alerts" && openAlertCount > 0 && (
                  <span className="bg-destructive text-destructive-foreground text-xs rounded-full px-1.5 py-0.5 min-w-[20px] text-center">
                    {openAlertCount}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-border">
          <div className="flex items-center gap-2 mb-2">
            <Activity size={14} className="text-primary" />
            <span className="text-xs text-muted-foreground">admin</span>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors w-full"
          >
            <LogOut size={14} />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        {children}
      </main>
    </div>
  );
}
