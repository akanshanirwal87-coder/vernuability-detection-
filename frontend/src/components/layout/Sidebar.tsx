import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldCheck, 
  LayoutDashboard, 
  Terminal, 
  History, 
  ShieldAlert, 
  FileCode2, 
  FileText, 
  BookOpen, 
  Settings, 
  ChevronLeft, 
  ChevronRight,
  GraduationCap,
  Brain,
  Database
} from 'lucide-react';

interface SidebarProps {
  onToggle: () => void;
  collapsed: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onToggle }) => {
  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'New Scan', path: '/scan', icon: Terminal, badge: 'SAST' },
    { name: 'Scan History', path: '/history', icon: History },
    { name: 'Vulnerabilities', path: '/results/scan-demo-01', icon: ShieldAlert },
    { name: 'AI Remediation', path: '/remediation/scan-demo-01', icon: FileCode2 },
    { name: 'Model & Datasets', path: '/model-datasets', icon: Brain, badge: 'OSV+ME' },
    { name: 'Reports', path: '/reports', icon: FileText },
    { name: 'Documentation', path: '/docs', icon: BookOpen },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <aside 
      className={`fixed top-0 left-0 z-40 h-screen transition-all duration-300 bg-sidebar border-r border-border flex flex-col justify-between ${
        collapsed ? 'w-20' : 'w-64'
      }`}
    >
      <div>
        {/* Brand & Logo */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-border">
          <NavLink to="/" className="flex items-center gap-3 overflow-hidden">
            <div className="p-2 rounded-lg bg-primary/20 border border-primary/40 text-primary flex items-center justify-center shrink-0">
              <ShieldCheck className="w-5 h-5 text-blue-400" />
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="font-bold text-sm tracking-tight text-white flex items-center gap-1.5">
                  SecureCode <span className="text-cyan-400 font-mono text-xs">AI</span>
                </span>
                <span className="text-[10px] text-slate-400 font-mono">
                  v1.0 • SAST Engine
                </span>
              </div>
            )}
          </NavLink>
          <button
            onClick={onToggle}
            className="p-1.5 rounded-md hover:bg-surface text-slate-400 hover:text-white transition-colors"
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Links */}
        <nav className="p-3 space-y-1.5 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-primary/20 text-blue-400 border border-primary/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-surface/60'
                } ${collapsed ? 'justify-center' : ''}`
              }
              title={collapsed ? item.name : undefined}
            >
              <item.icon className="w-4 h-4 shrink-0" />
              {!collapsed && (
                <div className="flex items-center justify-between w-full">
                  <span>{item.name}</span>
                  {item.badge && (
                    <span className="text-[9px] font-mono px-1.5 py-0.2 bg-cyan-950/60 text-cyan-400 border border-cyan-800/60 rounded">
                      {item.badge}
                    </span>
                  )}
                </div>
              )}
            </NavLink>
          ))}
        </nav>
      </div>

      {/* Academic Project Info & Supervisor Tag */}
      {!collapsed ? (
        <div className="p-3 border-t border-border bg-[#0B1020]/60">
          <div className="p-2.5 rounded-lg bg-surface/50 border border-border text-[11px] text-slate-400 space-y-1">
            <div className="flex items-center gap-1.5 text-cyan-400 font-semibold text-[10px] uppercase tracking-wider">
              <GraduationCap className="w-3.5 h-3.5" />
              <span>B.Tech CSE (AI & ML)</span>
            </div>
            <p className="text-[10px] text-slate-300 leading-tight">
              Kurukshetra University • PIET
            </p>
            <p className="text-[9px] text-slate-400 pt-1 border-t border-border-light/40">
              Students: Akansha & Vanshika
            </p>
          </div>
        </div>
      ) : (
        <div className="p-3 border-t border-border flex justify-center">
          <span title="B.Tech CSE (AI & ML) Minor Project">
            <GraduationCap className="w-4 h-4 text-slate-500" />
          </span>
        </div>
      )}
    </aside>
  );
};
