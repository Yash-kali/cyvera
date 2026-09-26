import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { useScanTelemetry } from '../context/ScanContext';
import {
  Menu,
  Search,
  Bell,
  User,
  LogOut,
  ChevronDown,
  Key,
  Command,
  Shield,
  Activity,
  CheckCircle2
} from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';

interface NavbarProps {
  onToggleSidebar: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onToggleSidebar }) => {
  const { user, logout } = useAuth();
  const { scans, runningScansCount, securityScore, securityGrade } = useScanTelemetry();
  const navigate = useNavigate();
  const [notificationsOpen, setNotificationsOpen] = useState<boolean>(false);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [commandPaletteOpen, setCommandPaletteOpen] = useState<boolean>(false);

  const notifRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  // Close dropdowns on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setNotificationsOpen(false);
      }
      if (profileRef.current && !profileRef.current.contains(event.target as Node)) {
        setProfileDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Keyboard shortcut listener (Cmd/Ctrl + K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Real system notifications derived from backend scans
  const notifications = scans.slice(0, 5).map((s) => {
    const isCompleted = s.status?.toLowerCase() === 'completed';
    const isRunning = s.status?.toLowerCase() === 'running';
    return {
      id: s.id,
      title: isCompleted
        ? `Scan #${s.id} Completed`
        : isRunning
        ? `Scan #${s.id} In Progress`
        : `Scan #${s.id} Failed`,
      desc: `${s.target_url} (${s.scan_type} Profile) — ${s.vulnerabilities_count || 0} findings`,
      time: new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      level: (s.critical_count || 0) > 0 ? 'critical' : isCompleted ? 'success' : 'info',
    };
  });

  const gradeColor =
    securityScore !== null
      ? securityScore >= 85
        ? 'bg-cyber-emerald/20 text-cyber-emerald border-cyber-emerald/40'
        : securityScore >= 70
        ? 'bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/40'
        : securityScore >= 50
        ? 'bg-cyber-amber/20 text-cyber-amber border-cyber-amber/40'
        : 'bg-cyber-rose/20 text-cyber-rose border-cyber-rose/40'
      : 'bg-white/5 text-slate-400 border-white/10';

  return (
    <>
      <header className="sticky top-0 z-30 h-16 bg-[#070b12]/90 backdrop-blur-md border-b border-white/10 flex items-center justify-between px-4 sm:px-6 font-sans">
        
        {/* Left Section: Mobile Menu & Global Search Bar */}
        <div className="flex items-center space-x-4 flex-1 max-w-md">
          <button
            onClick={onToggleSidebar}
            className="lg:hidden p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
            title="Open Menu"
          >
            <Menu className="w-5 h-5" />
          </button>

          {/* Enterprise Global Search Button */}
          <button
            onClick={() => setCommandPaletteOpen(true)}
            className="hidden sm:flex items-center space-x-3 px-3.5 py-1.5 rounded-xl bg-[#0b101d] border border-white/10 hover:border-white/20 transition-all text-xs font-mono text-slate-400 hover:text-slate-200 group w-full"
          >
            <Search className="w-3.5 h-3.5 text-slate-400 group-hover:text-cyber-cyan transition-colors" />
            <span className="flex-1 text-left truncate text-xs font-sans">Global search target scope, CVEs...</span>
            <kbd className="inline-flex items-center space-x-0.5 px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[10px] text-slate-400 font-mono">
              <Command className="w-2.5 h-2.5" />
              <span>K</span>
            </kbd>
          </button>
        </div>

        {/* Center Section: Current Scan Status & Security Score summary pills */}
        <div className="hidden lg:flex items-center space-x-4 font-mono text-xs">
          <div className="flex items-center space-x-2 px-3 py-1 rounded-xl bg-white/[0.03] border border-white/10 text-slate-300">
            <Activity className={`w-3.5 h-3.5 ${runningScansCount > 0 ? 'text-cyber-cyan animate-pulse' : 'text-slate-400'}`} />
            <span className="text-[11px] font-medium">Scan Status:</span>
            {runningScansCount > 0 ? (
              <span className="text-cyber-emerald font-bold text-[11px] flex items-center space-x-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-emerald animate-ping" />
                <span>ACTIVE ({runningScansCount} RUNNING)</span>
              </span>
            ) : (
              <span className="text-slate-400 font-bold text-[11px]">STANDBY (0 RUNNING)</span>
            )}
          </div>

          <div className="flex items-center space-x-2 px-3 py-1 rounded-xl bg-white/[0.03] border border-white/10 text-slate-300">
            <Shield className={`w-3.5 h-3.5 ${securityScore !== null && securityScore >= 70 ? 'text-cyber-emerald' : 'text-cyber-cyan'}`} />
            <span className="text-[11px] font-medium">Security Score:</span>
            {securityScore !== null ? (
              <>
                <span className="text-slate-100 font-bold text-[11px]">{securityScore} / 100</span>
                <span className={`px-1.5 py-0.5 rounded border font-bold text-[10px] ${gradeColor}`}>
                  {securityGrade?.startsWith('GRADE') ? securityGrade : `GRADE ${securityGrade || 'A'}`}
                </span>
              </>
            ) : (
              <>
                <span className="text-slate-400 font-bold text-[11px]">-- / 100</span>
                <span className="px-1.5 py-0.5 rounded border bg-white/5 text-slate-400 border-white/10 font-bold text-[10px]">
                  STANDBY
                </span>
              </>
            )}
          </div>
        </div>

        {/* Right Section: Notifications & User Profile */}
        <div className="flex items-center space-x-3 font-mono">
          
          {/* Notifications Dropdown */}
          <div className="relative" ref={notifRef}>
            <button
              onClick={() => setNotificationsOpen(!notificationsOpen)}
              className="relative p-2 rounded-xl bg-[#0b101d] border border-white/10 hover:border-white/20 text-slate-300 hover:text-white transition-colors"
              title="Notifications"
            >
              <Bell className="w-4 h-4" />
              {notifications.length > 0 && (
                <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-cyber-cyan" />
              )}
            </button>

            {/* Dropdown Menu */}
            {notificationsOpen && (
              <div className="absolute right-0 mt-2 w-80 sm:w-96 glass-card rounded-2xl p-4 space-y-3 z-50 border border-white/15 shadow-2xl">
                <div className="flex items-center justify-between border-b border-white/10 pb-3">
                  <span className="font-bold text-xs text-slate-100 font-display uppercase tracking-wider">
                    System Alerts
                  </span>
                  <span className="px-2 py-0.5 text-[10px] bg-cyber-cyan/20 text-cyber-cyan rounded-full font-bold">
                    {notifications.length} RECENT
                  </span>
                </div>

                <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                  {notifications.length === 0 ? (
                    <div className="py-6 text-center text-slate-500 font-mono text-xs">
                      No recent security alerts recorded.
                    </div>
                  ) : (
                    notifications.map((n) => (
                      <div key={n.id} className="p-3 rounded-xl bg-white/[0.03] border border-white/5 text-xs space-y-1">
                        <div className="flex items-center justify-between font-semibold">
                          <span className={n.level === 'critical' ? 'text-cyber-rose' : n.level === 'success' ? 'text-cyber-emerald' : 'text-cyber-cyan'}>
                            {n.title}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono">{n.time}</span>
                        </div>
                        <p className="text-slate-400 text-[11px] font-sans truncate">{n.desc}</p>
                      </div>
                    ))
                  )}
                </div>

                <div className="pt-2 border-t border-white/10 text-center">
                  <Link
                    to="/vulnerabilities"
                    onClick={() => setNotificationsOpen(false)}
                    className="text-xs text-cyber-cyan hover:underline font-semibold font-sans"
                  >
                    View Findings Center →
                  </Link>
                </div>
              </div>
            )}
          </div>

          {/* User Profile Menu */}
          {user && (
            <div className="relative" ref={profileRef}>
              <button
                onClick={() => setProfileDropdownOpen(!profileDropdownOpen)}
                className="flex items-center space-x-2.5 p-1.5 rounded-xl bg-[#0b101d] border border-white/10 hover:border-white/20 transition-colors text-xs"
              >
                <div className="w-7 h-7 rounded-lg bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan flex items-center justify-center font-bold font-display">
                  {user.username.charAt(0).toUpperCase()}
                </div>
                <span className="hidden sm:inline-block font-semibold text-slate-200 font-sans">{user.username}</span>
                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>

              {/* Profile Dropdown */}
              {profileDropdownOpen && (
                <div className="absolute right-0 mt-2 w-56 glass-card rounded-2xl p-2 z-50 text-xs space-y-1 border border-white/15 shadow-2xl">
                  <div className="p-3 border-b border-white/10 space-y-1">
                    <div className="font-bold text-slate-100 font-display text-sm">{user.username}</div>
                    <div className="text-[11px] text-slate-400 truncate font-sans">{user.email}</div>
                  </div>

                  <Link
                    to="/profile"
                    onClick={() => setProfileDropdownOpen(false)}
                    className="flex items-center space-x-2 px-3 py-2 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition-colors font-sans"
                  >
                    <User className="w-4 h-4 text-slate-400" />
                    <span>Operator Profile</span>
                  </Link>

                  <Link
                    to="/settings"
                    onClick={() => setProfileDropdownOpen(false)}
                    className="flex items-center space-x-2 px-3 py-2 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition-colors font-sans"
                  >
                    <Key className="w-4 h-4 text-slate-400" />
                    <span>Settings & API</span>
                  </Link>

                  <div className="pt-1 border-t border-white/10">
                    <button
                      onClick={() => {
                        setProfileDropdownOpen(false);
                        logout();
                      }}
                      className="w-full flex items-center space-x-2 px-3 py-2 rounded-xl text-cyber-rose hover:bg-cyber-rose/10 transition-colors font-semibold font-sans"
                    >
                      <LogOut className="w-4 h-4" />
                      <span>Sign Out</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

        </div>
      </header>

      {/* Command Palette Modal */}
      {commandPaletteOpen && (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-xl glass-card rounded-2xl border border-white/15 p-4 space-y-4 shadow-2xl">
            <div className="flex items-center space-x-3 pb-3 border-b border-white/10">
              <Search className="w-5 h-5 text-cyber-cyan" />
              <input
                type="text"
                autoFocus
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search target scope, CVEs, findings..."
                className="w-full bg-transparent text-slate-100 placeholder-slate-500 font-sans outline-none text-sm"
              />
              <button
                onClick={() => setCommandPaletteOpen(false)}
                className="text-xs text-slate-500 hover:text-slate-300 font-mono px-2 py-1 rounded bg-white/5"
              >
                ESC
              </button>
            </div>

            <div className="space-y-1 text-xs font-sans">
              <div className="text-[10px] text-slate-500 font-mono uppercase tracking-wider px-2 py-1">Navigation</div>
              <button
                onClick={() => { setCommandPaletteOpen(false); navigate('/scans/new'); }}
                className="w-full flex items-center justify-between p-2.5 rounded-xl hover:bg-white/5 text-slate-200 font-sans transition-all text-left"
              >
                <div className="flex items-center space-x-2.5">
                  <Shield className="w-4 h-4 text-cyber-cyan" />
                  <span>Launch Target Pentest</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500">/scans/new</span>
              </button>
              <button
                onClick={() => { setCommandPaletteOpen(false); navigate('/vulnerabilities'); }}
                className="w-full flex items-center justify-between p-2.5 rounded-xl hover:bg-white/5 text-slate-200 font-sans transition-all text-left"
              >
                <div className="flex items-center space-x-2.5">
                  <CheckCircle2 className="w-4 h-4 text-cyber-rose" />
                  <span>Vulnerability Findings</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500">/vulnerabilities</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
