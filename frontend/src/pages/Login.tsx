import React, { useState } from 'react';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, User, AlertCircle, ArrowRight, CheckCircle2 } from 'lucide-react';
import { motion } from 'framer-motion';

export const Login: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/dashboard';
  const successMessage = (location.state as { message?: string })?.message;

  const [formData, setFormData] = useState({
    email_or_username: '',
    password: '',
  });
  const [rememberMe, setRememberMe] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.email_or_username || !formData.password) {
      setError('Please fill in all credentials.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await login(formData);
      navigate(from, { replace: true });
    } catch (err: any) {
      console.error('Login failed:', err);
      const detail = err.response?.data?.detail;
      if (typeof detail === 'string') {
        setError(detail);
      } else if (Array.isArray(detail)) {
        setError(detail.map((d) => d.msg).join(', '));
      } else {
        setError('Authentication failed. Please verify your credentials and try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070707] flex items-center justify-center p-4 relative overflow-hidden font-sans selection:bg-cyber-cyan selection:text-slate-950">
      
      {/* Glow Orbs */}
      <div className="absolute top-1/4 left-1/3 w-96 h-96 bg-cyber-cyan/10 rounded-full blur-[140px] pointer-events-none animate-pulse-glow" />
      <div className="absolute bottom-1/4 right-1/3 w-96 h-96 bg-cyber-purple/15 rounded-full blur-[140px] pointer-events-none animate-pulse-glow" />

      <div className="w-full max-w-md relative z-10 space-y-6">
        
        {/* Header Branding */}
        <div className="text-center space-y-3">
          <Link to="/" className="inline-flex p-3 rounded-2xl bg-gradient-to-br from-cyber-cyan/20 to-cyber-purple/30 border border-cyber-cyan/40 shadow-glow-cyan">
            <Shield className="w-8 h-8 text-cyber-cyan" />
          </Link>
          <h1 className="text-3xl font-bold font-display text-slate-100 tracking-tight">
            Cyvera Security Console
          </h1>
          <p className="text-xs font-mono text-slate-400">
            Authorized Personnel Access Only
          </p>
        </div>

        {/* Success Alert Box */}
        {successMessage && (
          <div className="p-4 rounded-2xl bg-cyber-emerald/10 border border-cyber-emerald/40 flex items-start space-x-3 text-cyber-emerald text-xs font-mono">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <div className="flex-1">{successMessage}</div>
          </div>
        )}

        {/* Error Alert Box */}
        {error && (
          <div className="p-4 rounded-2xl bg-cyber-rose/10 border border-cyber-rose/40 flex items-start space-x-3 text-cyber-rose text-xs font-mono animate-shake">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <div className="flex-1">{error}</div>
          </div>
        )}

        {/* Main Form Card */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="glass-card p-8 rounded-3xl border border-white/10 shadow-2xl relative overflow-hidden space-y-5"
        >
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyber-cyan via-cyber-purple to-cyber-emerald"></div>

          <form onSubmit={handleSubmit} className="space-y-4">
            
            {/* Username/Email Input */}
            <div className="space-y-1.5">
              <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Email or Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  required
                  value={formData.email_or_username}
                  onChange={(e) => setFormData({ ...formData, email_or_username: e.target.value })}
                  placeholder="Enter email or username"
                  className="w-full pl-10 pr-4 py-3 rounded-xl bg-white/[0.03] border border-white/10 focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan text-slate-100 placeholder-slate-500 text-xs font-mono transition-all outline-none"
                />
              </div>
            </div>

            {/* Password Input */}
            <div className="space-y-1.5">
              <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  required
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  placeholder="Enter password"
                  className="w-full pl-10 pr-4 py-3 rounded-xl bg-white/[0.03] border border-white/10 focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan text-slate-100 placeholder-slate-500 text-xs font-mono transition-all outline-none"
                />
              </div>
            </div>

            {/* Options */}
            <div className="flex items-center justify-between text-xs font-mono pt-1">
              <label className="flex items-center space-x-2 cursor-pointer text-slate-400 hover:text-slate-200">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="rounded border-white/20 bg-white/5 text-cyber-cyan focus:ring-0"
                />
                <span>Persist Session</span>
              </label>
              <span className="text-slate-500 text-[11px]">Strict TLS &bull; Pinning</span>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3.5 px-4 rounded-xl bg-gradient-to-r from-cyber-cyan to-cyber-purple hover:opacity-95 text-slate-950 font-mono font-bold text-xs tracking-wider uppercase transition-all shadow-glow-cyan flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed mt-2"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></div>
                  <span>AUTHENTICATING...</span>
                </>
              ) : (
                <>
                  <span>SIGN IN</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          <div className="pt-4 border-t border-white/10 text-center text-xs font-mono text-slate-500">
            Private Access Control &bull; Self-registration disabled
          </div>
        </motion.div>

        {/* Security Footer Notice */}
        <div className="text-center text-[11px] font-mono text-slate-500 flex items-center justify-center space-x-1.5">
          <CheckCircle2 className="w-3.5 h-3.5 text-cyber-emerald" />
          <span>Encrypted with SHA-256 & Bcrypt password protection</span>
        </div>

      </div>
    </div>
  );
};
