import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Target,
  PlusCircle,
  ShieldAlert,
  FileText,
  Settings,
  Shield,
  X,
  ChevronDown,
  Globe,
  BarChart3,
  User,
  Terminal,
  Activity
} from 'lucide-react';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  const [advancedOpen, setAdvancedOpen] = useState<boolean>(false);

  const primaryNavItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'New Scan', path: '/scans/new', icon: PlusCircle, highlight: true },
    { name: 'Scan History', path: '/scans', icon: Target },
    { name: 'Findings', path: '/vulnerabilities', icon: ShieldAlert },
    { name: 'Reports', path: '/reports', icon: FileText },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  const secondaryNavItems = [
    { name: 'Analytics', path: '/analytics', icon: BarChart3 },
    { name: 'Risk Analytics', path: '/analytics/risk', icon: Activity },
    { name: 'Asset Recon', path: '/recon', icon: Globe },
    { name: 'Operator Profile', path: '/profile', icon: User },
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/80 backdrop-blur-sm lg:hidden transition-opacity"
          onClick={onClose}
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-0 left-0 z-50 h-full w-64 bg-[#070b12] border-r border-white/10 flex flex-col justify-between transition-transform duration-300 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div>
          {/* Brand Header */}
          <div className="h-16 px-6 flex items-center justify-between border-b border-white/10">
            <NavLink to="/dashboard" className="flex items-center space-x-3 group">
              <div className="p-2 rounded-xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan group-hover:border-cyber-cyan transition-colors">
                <Shield className="w-5 h-5 text-cyber-cyan" />
              </div>
              <div>
                <div className="font-bold text-base tracking-tight font-display text-slate-100 flex items-center space-x-1">
                  <span>Cyvera</span>
                  <span className="text-cyber-cyan">.AI</span>
                </div>
                <div className="text-[9px] font-mono text-slate-400 tracking-widest uppercase">Security Operations</div>
              </div>
            </NavLink>

            {/* Mobile Close Button */}
            <button
              onClick={onClose}
              className="lg:hidden p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Core Navigation Links */}
          <nav className="p-3 space-y-1 font-sans text-xs">
            <div className="px-3 py-2 text-[10px] text-slate-500 font-mono uppercase tracking-wider font-semibold">
              Main Menu
            </div>

            {primaryNavItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  onClick={onClose}
                  className={({ isActive }) =>
                    `flex items-center space-x-3 px-3 py-2.5 rounded-xl font-medium transition-all ${
                      isActive
                        ? 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 font-bold shadow-glow-cyan/20'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                    }`
                  }
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.name}</span>
                </NavLink>
              );
            })}

            {/* Collapsible Advanced Tools Submenu */}
            <div className="pt-2">
              <button
                onClick={() => setAdvancedOpen((prev) => !prev)}
                className="w-full flex items-center justify-between px-3 py-2 text-slate-400 hover:text-slate-200 hover:bg-white/5 rounded-xl transition-colors font-mono text-[11px] uppercase tracking-wider font-semibold"
              >
                <div className="flex items-center space-x-2">
                  <Terminal className="w-4 h-4 text-cyber-purple" />
                  <span>Advanced Tools</span>
                </div>
                <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${advancedOpen ? 'rotate-180' : ''}`} />
              </button>

              {advancedOpen && (
                <div className="pl-6 pt-1 space-y-1">
                  {secondaryNavItems.map((sub) => {
                    const SubIcon = sub.icon;
                    return (
                      <NavLink
                        key={sub.path}
                        to={sub.path}
                        onClick={onClose}
                        className={({ isActive }) =>
                          `flex items-center space-x-2.5 px-3 py-2 rounded-xl text-xs transition-colors ${
                            isActive
                              ? 'text-cyber-cyan font-bold bg-white/5'
                              : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                          }`
                        }
                      >
                        <SubIcon className="w-3.5 h-3.5" />
                        <span>{sub.name}</span>
                      </NavLink>
                    );
                  })}
                </div>
              )}
            </div>

          </nav>
        </div>

        {/* Minimal Footer Info */}
        <div className="p-4 border-t border-white/10 font-mono text-[10px] text-slate-500 flex items-center justify-between">
          <span>Cyvera v1.0</span>
          <span className="text-cyber-emerald font-bold">OPERATIONAL</span>
        </div>

      </aside>
    </>
  );
};
