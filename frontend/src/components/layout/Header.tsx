import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { checkBackendHealth } from '../../services/apiClient';
import { 
  PlusCircle, 
  Server, 
  Bell, 
  User, 
  ShieldCheck, 
  ExternalLink,
  ChevronRight,
  Sparkles,
  Brain
} from 'lucide-react';

export const Header: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [backendOnline, setBackendOnline] = useState<boolean>(false);
  const [showNotifications, setShowNotifications] = useState<boolean>(false);

  useEffect(() => {
    checkBackendHealth().then(res => setBackendOnline(res.online));
    const interval = setInterval(() => {
      checkBackendHealth().then(res => setBackendOnline(res.online));
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  const getBreadcrumbs = () => {
    const path = location.pathname;
    if (path === '/') return 'Welcome';
    if (path.startsWith('/dashboard')) return 'Security Dashboard';
    if (path.startsWith('/scan')) return 'New Code Analysis';
    if (path.startsWith('/results')) return 'Scan Findings & Audit';
    if (path.startsWith('/remediation')) return 'AI Remediation Workspace';
    if (path.startsWith('/history')) return 'Scan History Archive';
    if (path.startsWith('/reports')) return 'Security Reports Center';
    if (path.startsWith('/model-datasets')) return 'AI Model & Datasets Intelligence';
    if (path.startsWith('/docs')) return 'Technical Documentation';
    if (path.startsWith('/settings')) return 'Application Settings';
    return 'Workspace';
  };

  return (
    <header className="h-16 bg-[#0B1020]/90 backdrop-blur border-b border-border sticky top-0 z-30 px-6 flex items-center justify-between">
      {/* Breadcrumbs & Title */}
      <div className="flex items-center gap-2 text-xs">
        <Link to="/" className="text-slate-400 hover:text-slate-200 transition-colors">
          SecureCode AI
        </Link>
        <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
        <span className="font-semibold text-slate-200 font-mono">
          {getBreadcrumbs()}
        </span>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* ML & Dataset Status Badge */}
        <Link
          to="/model-datasets"
          className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-purple-500/30 bg-purple-950/30 text-purple-300 text-[11px] font-mono hover:bg-purple-900/40 hover:border-purple-500/60 transition-all duration-200 hover:-translate-y-0.5"
          title="AI/ML Model trained on real-world datasets from OSV.dev and ManageEngine Endpoint Security"
        >
          <Brain className="w-3 h-3 text-purple-400" />
          <span>ML Model: OSV + ME</span>
        </Link>

        {/* Backend Status Indicator */}
        <div 
          className={`flex items-center gap-2 px-2.5 py-1 rounded-full border text-[11px] font-mono transition-all duration-200 ${
            backendOnline 
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-400' 
              : 'bg-amber-950/40 border-amber-800/60 text-amber-300'
          }`}
          title={backendOnline ? "FastAPI Backend Connected (Port 8000)" : "Running in Standalone / Demo Mode (FastAPI offline)"}
        >
          <div className={`w-2 h-2 rounded-full animate-pulse ${backendOnline ? 'bg-emerald-400' : 'bg-amber-400'}`} />
          <span>{backendOnline ? 'API Connected' : 'Demo Mode'}</span>
        </div>

        {/* Start New Scan CTA */}
        <button
          onClick={() => navigate('/scan')}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover active:scale-95 text-white text-xs font-medium transition-all duration-200 hover:-translate-y-0.5 shadow-sm shadow-blue-500/20"
        >
          <PlusCircle className="w-3.5 h-3.5" />
          <span>Start Scan</span>
        </button>

        {/* Notifications Popover */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-2 rounded-lg bg-surface border border-border text-slate-300 hover:text-white hover:border-border-light transition-all duration-200 hover:scale-105 active:scale-95 relative"
            title="System alerts"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-cyan-400" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-72 bg-card border border-border rounded-xl shadow-2xl p-3 z-50 text-xs animate-scale-in">
              <div className="flex items-center justify-between pb-2 border-b border-border">
                <span className="font-semibold text-white">System Notifications</span>
                <span className="text-[10px] text-cyan-400 font-mono">Active</span>
              </div>
              <div className="py-2 space-y-2">
                <div className="p-2 rounded bg-surface/40 border border-border-light/50">
                  <p className="font-medium text-slate-200">AST Analysis Engine Ready</p>
                  <p className="text-[10px] text-slate-400">Python 3.12 AST & pattern rules loaded.</p>
                </div>
                <div className="p-2 rounded bg-surface/40 border border-border-light/50">
                  <p className="font-medium text-slate-200">OWASP Top 10 Rules Active</p>
                  <p className="text-[10px] text-slate-400">CWE-89, CWE-78, CWE-798, CWE-22, CWE-79.</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Profile Tag */}
        <div className="flex items-center gap-2 pl-2 border-l border-border text-xs text-slate-300">
          <div className="w-7 h-7 rounded-full bg-surface border border-border flex items-center justify-center text-cyan-400 font-semibold text-xs">
            AI
          </div>
        </div>
      </div>
    </header>
  );
};

