import React, { useState } from 'react';
import { X, Lock, Mail, User, ShieldCheck, LogOut, Loader2 } from 'lucide-react';
import { loginUser, registerUser, logoutUser, UserProfile } from '../../services/apiClient';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUser: UserProfile | null;
  onAuthChange: (user: UserProfile | null) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  currentUser,
  onAuthChange,
}) => {
  const [isRegister, setIsRegister] = useState<boolean>(false);
  const [name, setName] = useState<string>('');
  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (isRegister) {
        if (!name.trim()) throw new Error('Name is required.');
        if (password.length < 8) throw new Error('Password must be at least 8 characters.');
        const user = await registerUser(name, email, password);
        onAuthChange(user);
        onClose();
      } else {
        const user = await loginUser(email, password);
        onAuthChange(user);
        onClose();
      }
    } catch (err: any) {
      const msg = err.response?.data?.message || err.message || 'Authentication failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await logoutUser();
    onAuthChange(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0B1020] border border-slate-700/80 rounded-xl shadow-2xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h3 className="font-semibold text-slate-100 text-sm">
              {currentUser ? 'Authenticated Profile' : (isRegister ? 'Create Secure Account' : 'Sign In to SecureCode AI')}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors p-1 rounded-lg hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          {currentUser ? (
            /* Logged In View */
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold">
                    {currentUser.name.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <h4 className="font-medium text-slate-100 text-sm">{currentUser.name}</h4>
                    <p className="text-xs text-slate-400">{currentUser.email}</p>
                  </div>
                </div>
                <div className="mt-3 pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
                  <span className="text-slate-400">Assigned Role:</span>
                  <span className="px-2 py-0.5 rounded font-mono text-[10px] font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
                    {currentUser.role}
                  </span>
                </div>
              </div>

              <button
                onClick={handleLogout}
                className="w-full py-2 px-4 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/60 text-rose-300 font-medium text-xs flex items-center justify-center gap-2 transition-colors"
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign Out
              </button>
            </div>
          ) : (
            /* Auth Form */
            <div>
              {/* Tabs */}
              <div className="flex rounded-lg bg-slate-900/80 p-1 mb-5 border border-slate-800">
                <button
                  type="button"
                  onClick={() => { setIsRegister(false); setError(null); }}
                  className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-all ${
                    !isRegister ? 'bg-cyan-500 text-slate-950 shadow' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Sign In
                </button>
                <button
                  type="button"
                  onClick={() => { setIsRegister(true); setError(null); }}
                  className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-all ${
                    isRegister ? 'bg-cyan-500 text-slate-950 shadow' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Register
                </button>
              </div>

              {error && (
                <div className="mb-4 p-2.5 rounded-lg bg-rose-950/50 border border-rose-800/80 text-rose-200 text-xs">
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-3.5">
                {isRegister && (
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">Full Name</label>
                    <div className="relative">
                      <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="Alice Developer"
                        required={isRegister}
                        className="w-full pl-9 pr-3 py-2 bg-slate-900/90 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-cyan-400 transition-colors"
                      />
                    </div>
                  </div>
                )}

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Email Address</label>
                  <div className="relative">
                    <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="developer@example.com"
                      required
                      className="w-full pl-9 pr-3 py-2 bg-slate-900/90 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-cyan-400 transition-colors"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Password</label>
                  <div className="relative">
                    <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      required
                      className="w-full pl-9 pr-3 py-2 bg-slate-900/90 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-cyan-400 transition-colors"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-2 py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                >
                  {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  {isRegister ? 'Create Account' : 'Sign In'}
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
