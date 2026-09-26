import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, User, Mail, Key, AlertCircle, ArrowRight, CheckCircle2 } from 'lucide-react';
import { motion } from 'framer-motion';

export const Register: React.FC = () => {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    admin_invite_token: '',
  });
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.username || !formData.email || !formData.password || !formData.confirmPassword) {
      setError('Please fill in all required fields.');
      return;
    }

    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await register({
        username: formData.username,
        email: formData.email,
        password: formData.password,
        admin_invite_token: formData.admin_invite_token || undefined,
      });
      navigate('/dashboard', { replace: true });
    } catch (err: any) {
      console.error('Registration failed:', err);
      const detail = err.response?.data?.detail;
      if (typeof detail === 'string') {
        setError(detail);
      } else if (Array.isArray(detail)) {
        setError(detail.map((d) => d.msg).join(', '));
      } else {
        setError('Registration failed. Username or email may already be in use.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070707] flex items-center justify-center p-4 relative overflow-hidden font-sans selection:bg-cyber-cyan selection:text-slate-950">
      
      {/* Glow Orbs */}
      <div className="absolute top-1/4 right-1/3 w-96 h-96 bg-cyber-purple/15 rounded-full blur-[140px] pointer-events-none animate-pulse-glow" />
      <div className="absolute bottom-1/4 left-1/3 w-96 h-96 bg-cyber-cyan/10 rounded-full blur-[140px] pointer-events-none animate-pulse-glow" />

      <div className="w-full max-w-md relative z-10 space-y-6">
        
        {/* Header Branding */}
        <div className="text-center space-y-3">
          <Link to="/" className="inline-flex p-3 rounded-2xl bg-gradient-to-br from-cyber-purple/20 to-cyber-cyan/30 border border-cyber-purple/40 shadow-glow-purple">
            <Shield className="w-8 h-8 text-cyber-purple" />
          </Link>
          <h1 className="text-3xl font-bold font-display text-slate-100 tracking-tight">
            Register Security Operator
          </h1>
          <p className="text-xs font-mono text-slate-400">
            Create your account to deploy autonomous security workflows
          </p>
        </div>

        {/* Error Alert Box */}
        {error && (
          <div className="p-4 rounded-2xl bg-cyber-rose/10 border border-cyber-rose/40 flex items-start space-x-3 text-cyber-rose text-xs font-mono animate-shake">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <div className="flex-1">{error}</div>
          </div>
        )}

        {/* Form Card */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="glass-card p-8 rounded-3xl border border-white/10 shadow-2xl relative overflow-hidden space-y-4"
        >
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyber-purple via-cyber-cyan to-cyber-emerald"></div>

          <form onSubmit={handleSubmit} className="space-y-3.5">
            
            {/* Username Input */}
            <div className="space-y-1">
              <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Operator Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  required
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  placeholder="cyber_lead"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-white/[0.03] border border-white/10 focus:border-cyber-purple focus:ring-1 focus:ring-cyber-purple text-slate-100 placeholder-slate-500 text-xs font-mono transition-all outline-none"
                />
              </div>
            </div>

            {/* Email Input */}
            <div className="space-y-1">
              <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Official Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  type="email"
                  required
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  placeholder="operator@company.com"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-white/[0.03] border border-white/10 focus:border-cyber-purple focus:ring-1 focus:ring-cyber-purple text-slate-100 placeholder-slate-500 text-xs font-mono transition-all outline-none"
                />
              </div>
            </div>

            {/* Password Input */}
            <div className="space-y-1">
              <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Security Passcode
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
                  placeholder="Min 6 characters"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-white/[0.03] border border-white/10 focus:border-cyber-purple focus:ring-1 focus:ring-cyber-purple text-slate-100 placeholder-slate-500 text-xs font-mono transition-all outline-none"
                />
              </div>
            </div>

            {/* Confirm Password Input */}
            <div className="space-y-1">
              <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Confirm Passcode
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  required
                  value={formData.confirmPassword}
                  onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                  placeholder="Repeat passcode"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-white/[0.03] border border-white/10 focus:border-cyber-purple focus:ring-1 focus:ring-cyber-purple text-slate-100 placeholder-slate-500 text-xs font-mono transition-all outline-none"
                />
              </div>
            </div>

            {/* Admin Invite Code */}
            <div className="space-y-1">
              <label className="block text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Admin Invite Code <span className="text-slate-500 font-normal lowercase">(required on private nodes)</span>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Key className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  value={formData.admin_invite_token}
                  onChange={(e) => setFormData({ ...formData, admin_invite_token: e.target.value })}
                  placeholder="Enter administrator bootstrap/invite token"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-white/[0.03] border border-white/10 focus:border-cyber-purple focus:ring-1 focus:ring-cyber-purple text-slate-100 placeholder-slate-500 text-xs font-mono transition-all outline-none"
                />
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-cyber-purple to-cyber-cyan hover:opacity-95 text-slate-950 font-mono font-bold text-xs tracking-wider uppercase transition-all shadow-glow-purple flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed pt-3"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></div>
                  <span>CREATING OPERATOR ACCOUNT...</span>
                </>
              ) : (
                <>
                  <span>REGISTER OPERATOR</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          <div className="pt-4 border-t border-white/10 text-center text-xs font-mono text-slate-400">
            Already registered?{' '}
            <Link to="/login" className="text-cyber-purple hover:underline font-bold">
              Sign In to Existing Session
            </Link>
          </div>
        </motion.div>

        {/* Footnote */}
        <div className="text-center text-[11px] font-mono text-slate-500 flex items-center justify-center space-x-1.5">
          <CheckCircle2 className="w-3.5 h-3.5 text-cyber-purple" />
          <span>PostgreSQL & SQLite async SQLAlchemy storage</span>
        </div>

      </div>
    </div>
  );
};
