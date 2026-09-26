import React, { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Zap,
  Lock,
  Terminal,
  Activity,
  Cpu,
  ArrowRight,
  CheckCircle2,
  Globe,
  Sparkles,
  BarChart3,
  FileText,
  Search,
  ChevronRight,
  ShieldCheck,
  Radio
} from 'lucide-react';
import { motion } from 'framer-motion';

export const Landing: React.FC = () => {
  const globeCanvasRef = useRef<HTMLCanvasElement | null>(null);

  // Animated 3D Cyber Globe Canvas effect
  useEffect(() => {
    const canvas = globeCanvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animFrame: number;
    let width = (canvas.width = 440);
    let height = (canvas.height = 440);
    const radius = 170;
    let rotation = 0;

    // Create latitude/longitude dots
    const dots: { x: number; y: number; z: number }[] = [];
    const latLines = 18;
    const longLines = 24;

    for (let i = 0; i <= latLines; i++) {
      const lat = (Math.PI * i) / latLines - Math.PI / 2;
      for (let j = 0; j < longLines; j++) {
        const lon = (2 * Math.PI * j) / longLines;
        const x = radius * Math.cos(lat) * Math.cos(lon);
        const y = radius * Math.sin(lat);
        const z = radius * Math.cos(lat) * Math.sin(lon);
        dots.push({ x, y, z });
      }
    }

    const render = () => {
      ctx.clearRect(0, 0, width, height);
      const cx = width / 2;
      const cy = height / 2;
      rotation += 0.006;

      // Draw latitude connection lines
      dots.forEach((dot) => {
        // Rotate around Y axis
        const cosR = Math.cos(rotation);
        const sinR = Math.sin(rotation);
        const rotX = dot.x * cosR - dot.z * sinR;
        const rotZ = dot.x * sinR + dot.z * cosR;

        // Perspective scale
        const scale = 300 / (300 + rotZ);
        const projX = cx + rotX * scale;
        const projY = cy + dot.y * scale;

        const alpha = Math.max(0.1, (rotZ + radius) / (2 * radius));
        ctx.beginPath();
        ctx.arc(projX, projY, 1.6 * scale, 0, Math.PI * 2);
        ctx.fillStyle = rotZ > 0 ? `rgba(0, 240, 255, ${alpha * 0.9})` : `rgba(112, 0, 255, ${alpha * 0.4})`;
        ctx.fill();
      });

      // Draw outer glowing halo ring
      ctx.beginPath();
      ctx.arc(cx, cy, radius + 10, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.15)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      animFrame = requestAnimationFrame(render);
    };

    render();

    return () => cancelAnimationFrame(animFrame);
  }, []);

  const features = [
    {
      icon: Terminal,
      title: 'Autonomous Pentest Engine',
      desc: 'Simulate sophisticated adversary TTPs across web apps, REST APIs, and microservice ingress gateways.',
      color: 'text-cyber-cyan',
      border: 'hover:border-cyber-cyan/50',
    },
    {
      icon: Cpu,
      title: 'Gemini AI Advisory System',
      desc: 'Generates structured 6-section vulnerability analysis reports with technical root cause, business impact, and developer fix guidance.',
      color: 'text-cyber-purple',
      border: 'hover:border-cyber-purple/50',
    },
    {
      icon: Activity,
      title: 'CVSS Risk Calculation',
      desc: 'Mathematical risk scoring engine calculating Security Health Scores (S) and domain security ratings (A+ to F).',
      color: 'text-cyber-emerald',
      border: 'hover:border-cyber-emerald/50',
    },
    {
      icon: Lock,
      title: 'Asset Security & TLS Audit',
      desc: 'Automated inspection of TLS certificate expiration, HSTS compliance, CSP rules, and IPv4 resolution.',
      color: 'text-cyber-amber',
      border: 'hover:border-cyber-amber/50',
    },
    {
      icon: BarChart3,
      title: 'Recharts Visual Analytics',
      desc: 'Interactive 4-card analytics suite with threat radar charts, severity donut breakdowns, and SLA tracking.',
      color: 'text-cyber-cyan',
      border: 'hover:border-cyber-cyan/50',
    },
    {
      icon: FileText,
      title: 'ReportLab PDF Generator',
      desc: 'Compile executive 9-section vulnerability reports ready for board distribution with 1-click browser download.',
      color: 'text-cyber-purple',
      border: 'hover:border-cyber-purple/50',
    },
  ];

  const workflowSteps = [
    { step: '01', title: 'Target Reconnaissance', desc: 'IPv4 DNS resolution, HTTP header audit, TLS certificate health.' },
    { step: '02', title: 'Vulnerability Scanning', desc: 'Deep attack surface evaluation checking BOLA, SQLi, XSS & CVEs.' },
    { step: '03', title: 'CVSS Risk Scoring', desc: 'Mathematical weight calculation assigning security letter grade (A+ to F).' },
    { step: '04', title: 'Gemini AI Advisory', desc: 'Synthesizing 6-section executive advisories & OWASP Top 10 mappings.' },
    { step: '05', title: 'Remediation Triage', desc: 'Vulnerability lifecycle tracking from Open to Mitigated & Resolved.' },
    { step: '06', title: 'Executive PDF Export', desc: 'Instant ReportLab PDF generation for C-suite and security auditors.' },
  ];

  return (
    <div className="min-h-screen bg-[#070707] text-slate-100 font-sans relative overflow-x-hidden selection:bg-cyber-cyan selection:text-slate-950">
      
      {/* Top Marketing Navigation */}
      <header className="sticky top-0 z-40 h-20 bg-[#070707]/80 backdrop-blur-xl border-b border-white/10">
        <div className="max-w-7xl mx-auto h-full px-6 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-3 group">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyber-cyan/20 to-cyber-purple/30 border border-cyber-cyan/40 shadow-glow-cyan">
              <Shield className="w-6 h-6 text-cyber-cyan group-hover:scale-110 transition-transform" />
            </div>
            <div>
              <div className="font-bold text-xl font-display text-slate-100 flex items-center space-x-1">
                <span>AutoPentest</span>
                <span className="text-cyber-cyan">.AI</span>
              </div>
              <span className="text-[10px] font-mono text-slate-400 tracking-widest uppercase">Autonomous Cybersecurity Operations</span>
            </div>
          </Link>

          <div className="hidden md:flex items-center space-x-8 text-xs font-mono text-slate-300">
            <a href="#features" className="hover:text-cyber-cyan transition-colors">Features</a>
            <a href="#workflow" className="hover:text-cyber-cyan transition-colors">Workflow</a>
            <a href="#stats" className="hover:text-cyber-cyan transition-colors">Metrics</a>
            <a href="#architecture" className="hover:text-cyber-cyan transition-colors">Architecture</a>
          </div>

          <div className="flex items-center space-x-4">
            <Link
              to="/login"
              className="px-4 py-2 rounded-xl text-xs font-mono text-slate-300 hover:text-white hover:bg-white/5 transition-all"
            >
              Sign In
            </Link>
            <Link
              to="/dashboard"
              className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyber-cyan to-cyber-purple hover:opacity-90 text-slate-950 font-mono font-bold text-xs shadow-glow-cyan flex items-center space-x-2 transition-all"
            >
              <span>Launch Command Center</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative pt-16 pb-24 px-6 max-w-7xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          
          {/* Hero Content */}
          <div className="lg:col-span-7 space-y-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan text-xs font-mono"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Enterprise Autonomous Security Platform</span>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="text-4xl sm:text-6xl font-bold font-display tracking-tight leading-[1.1]"
            >
              AI-Powered <span className="text-gradient-cyan">Autonomous Security</span> Intelligence.
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="text-slate-300 text-base sm:text-lg leading-relaxed max-w-2xl font-sans"
            >
              Next-generation autonomous penetration testing, holographic threat visualization, and real-time Google Gemini AI vulnerability intelligence.
            </motion.p>


            {/* Live Instant URL Auditor Form */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.25 }}
              className="glass-card p-2 sm:p-2.5 rounded-2xl border border-cyber-cyan/40 shadow-glow-cyan max-w-2xl"
            >
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const form = e.currentTarget;
                  const input = form.querySelector('input') as HTMLInputElement;
                  if (input && input.value) {
                    window.location.href = `/recon?target=${encodeURIComponent(input.value)}`;
                  }
                }}
                className="flex flex-col sm:flex-row items-center gap-2"
              >
                <div className="relative flex-1 w-full">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500 font-mono text-xs">
                    <Search className="w-4 h-4 text-cyber-cyan" />
                  </div>
                  <input
                    type="url"
                    required
                    placeholder="Paste any URL or domain (e.g., https://example.com)"
                    className="w-full pl-10 pr-4 py-3 rounded-xl bg-[#0b101d] border border-white/10 text-slate-100 placeholder-slate-500 font-mono text-xs outline-none focus:border-cyber-cyan transition-all"
                  />
                </div>
                <button
                  type="submit"
                  className="w-full sm:w-auto px-6 py-3 rounded-xl bg-gradient-to-r from-cyber-cyan to-cyber-purple hover:opacity-90 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider shadow-glow-cyan flex items-center justify-center space-x-2 transition-all flex-shrink-0"
                >
                  <span>RUN INSTANT AUDIT</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </form>
            </motion.div>

            {/* CTAs */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              className="flex flex-col sm:flex-row items-stretch sm:items-center space-y-3 sm:space-y-0 sm:space-x-4 font-mono text-xs"
            >
              <Link
                to="/dashboard"
                className="px-6 py-3.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-200 hover:text-white font-bold text-xs flex items-center justify-center space-x-2 transition-all border border-white/10"
              >
                <span>OPEN SOC COMMAND CENTER</span>
                <ArrowRight className="w-4 h-4 text-cyber-cyan" />
              </Link>
              <Link
                to="/login"
                className="px-6 py-3.5 rounded-xl glass-card text-slate-300 hover:text-white font-semibold text-xs flex items-center justify-center space-x-2 transition-all border border-white/10"
              >
                <Lock className="w-4 h-4 text-cyber-purple" />
                <span>OPERATOR SIGN IN</span>
              </Link>
            </motion.div>

            {/* Status Checklist */}
            <div className="pt-4 grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs font-mono text-slate-400">
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-cyber-emerald flex-shrink-0" />
                <span>Zero Trust Architecture</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-cyber-cyan flex-shrink-0" />
                <span>Gemini 1.5 Pro Advisory</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-cyber-purple flex-shrink-0" />
                <span>ReportLab PDF Engine</span>
              </div>
            </div>
          </div>

          {/* Hero 3D Globe Visual */}
          <div className="lg:col-span-5 flex justify-center relative">
            <div className="relative">
              {/* Glowing canvas backdrop */}
              <div className="absolute -inset-4 bg-gradient-to-r from-cyber-cyan/20 to-cyber-purple/20 rounded-full blur-3xl" />
              
              <canvas
                ref={globeCanvasRef}
                className="relative z-10 w-[380px] h-[380px] sm:w-[440px] sm:h-[440px]"
              />

              {/* Floating Stat Badge Widget */}
              <div className="absolute -bottom-2 -left-4 z-20 glass-card p-4 rounded-2xl border border-cyber-cyan/40 shadow-glow-cyan space-y-1 font-mono text-xs max-w-xs animate-float">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-slate-400 uppercase">Live Risk Assessment</span>
                  <span className="px-2 py-0.5 rounded bg-cyber-emerald/20 text-cyber-emerald font-bold text-[10px]">GRADE A+</span>
                </div>
                <div className="text-sm font-bold text-slate-100 font-display">Security Score: 94.8 / 100</div>
                <div className="text-[10px] text-slate-400">0 Critical Vulnerabilities Open</div>
              </div>
            </div>
          </div>

        </div>
      </section>

      {/* Features Bento Section */}
      <section id="features" className="py-20 px-6 max-w-7xl mx-auto border-t border-white/10">
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyber-purple/10 border border-cyber-purple/30 text-cyber-purple text-xs font-mono">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>COMMERCIAL SAAS CAPABILITIES</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-bold font-display tracking-tight">
            Engineered for Modern <span className="text-gradient-purple">Security Operations</span>
          </h2>
          <p className="text-slate-400 text-sm sm:text-base font-sans">
            Comprehensive offensive posture analysis, real-time threat telemetry, and automated remediation workflows.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((f, i) => {
            const Icon = f.icon;
            return (
              <motion.div
                key={i}
                whileHover={{ y: -6 }}
                transition={{ duration: 0.2 }}
                className={`glass-card p-6 rounded-3xl border border-white/10 ${f.border} space-y-4 relative overflow-hidden group`}
              >
                <div className="w-12 h-12 rounded-2xl bg-white/[0.04] border border-white/10 flex items-center justify-center group-hover:scale-110 transition-transform">
                  <Icon className={`w-6 h-6 ${f.color}`} />
                </div>
                <h3 className="text-lg font-bold font-display text-slate-100">{f.title}</h3>
                <p className="text-slate-400 text-xs sm:text-sm font-sans leading-relaxed">{f.desc}</p>
                <div className="pt-2 flex items-center text-xs font-mono text-cyber-cyan group-hover:underline">
                  <span>Learn more</span>
                  <ChevronRight className="w-3.5 h-3.5 ml-1" />
                </div>
              </motion.div>
            );
          })}
        </div>
      </section>

      {/* Workflow Timeline Section */}
      <section id="workflow" className="py-20 px-6 max-w-7xl mx-auto border-t border-white/10">
        <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan text-xs font-mono">
            <Radio className="w-3.5 h-3.5 animate-pulse" />
            <span>AUTOMATED ATTACK LIFECYCLE</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-bold font-display tracking-tight">
            6-Stage <span className="text-gradient-cyan">Penetration Workflow</span>
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {workflowSteps.map((s, i) => (
            <div key={i} className="glass-card p-6 rounded-3xl border border-white/10 space-y-3 relative">
              <div className="text-3xl font-bold font-mono text-cyber-cyan/40">{s.step}</div>
              <h4 className="text-base font-bold font-display text-slate-100">{s.title}</h4>
              <p className="text-slate-400 text-xs font-sans leading-relaxed">{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Metrics Section */}
      <section id="stats" className="py-16 px-6 max-w-7xl mx-auto border-t border-white/10">
        <div className="glass-card p-10 rounded-3xl border border-cyber-cyan/30 grid grid-cols-2 md:grid-cols-4 gap-8 text-center font-mono">
          <div className="space-y-2">
            <div className="text-3xl sm:text-4xl font-bold text-cyber-cyan font-display">100%</div>
            <div className="text-xs text-slate-400">Autonomous Execution</div>
          </div>
          <div className="space-y-2">
            <div className="text-3xl sm:text-4xl font-bold text-cyber-purple font-display">6-Sec</div>
            <div className="text-xs text-slate-400">Gemini AI Advisories</div>
          </div>
          <div className="space-y-2">
            <div className="text-3xl sm:text-4xl font-bold text-cyber-emerald font-display">9-Sec</div>
            <div className="text-xs text-slate-400">PDF Executive Reports</div>
          </div>
          <div className="space-y-2">
            <div className="text-3xl sm:text-4xl font-bold text-cyber-amber font-display">CVSS v3.1</div>
            <div className="text-xs text-slate-400">Standardized Scoring</div>
          </div>
        </div>
      </section>

      {/* Commercial Enterprise Footer */}
      <footer className="border-t border-white/10 py-12 px-6 max-w-7xl mx-auto font-mono text-xs text-slate-400">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center space-x-3">
            <Shield className="w-5 h-5 text-cyber-cyan" />
            <span className="font-bold font-display text-slate-100">AutoPentest AI Platform</span>
            <span>© 2026 Enterprise Security Operations</span>
          </div>

          <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald text-[11px]">
            <span className="w-2 h-2 rounded-full bg-cyber-emerald animate-ping" />
            <span>SYSTEM STATUS: ALL SYSTEMS OPERATIONAL</span>
          </div>
        </div>
      </footer>

    </div>
  );
};
