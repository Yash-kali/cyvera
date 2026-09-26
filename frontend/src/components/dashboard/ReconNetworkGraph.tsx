import React, { useEffect, useRef } from 'react';
import { Network } from 'lucide-react';
import { motion } from 'framer-motion';
import { ReconResult } from '../../api/recon';

interface ReconNetworkGraphProps {
  recon?: ReconResult | null;
}

export const ReconNetworkGraph: React.FC<ReconNetworkGraphProps> = ({ recon }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = canvas.parentElement?.clientWidth || 500);
    let height = (canvas.height = 260);

    const rootLabel = recon ? recon.target_url.replace(/^https?:\/\//, '') : 'No Target Scanned';
    const ipLabel = recon?.ip_address ? `IP: ${recon.ip_address}` : 'DNS / IPv4 Probe';
    const sslLabel = recon?.ssl_issuer ? `${recon.ssl_issuer.slice(0, 18)}` : 'TLS / SSL Certificate';
    const portLabel = '443 / HTTPS';
    const techLabel = recon?.web_server ? `Server: ${recon.web_server.slice(0, 16)}` : 'Server / Tech Signature';

    const nodes = [
      { id: 'Root', label: rootLabel, x: width * 0.5, y: height * 0.5, color: '#00f0ff', r: 12 },
      { id: 'IP', label: ipLabel, x: width * 0.25, y: height * 0.3, color: '#7000ff', r: 8 },
      { id: 'SSL', label: sslLabel, x: width * 0.25, y: height * 0.7, color: '#00ff9d', r: 8 },
      { id: 'Port443', label: portLabel, x: width * 0.75, y: height * 0.3, color: '#00f0ff', r: 8 },
      { id: 'Tech', label: techLabel, x: width * 0.75, y: height * 0.7, color: '#ffb800', r: 8 },
    ];

    const links = [
      { source: 0, target: 1 },
      { source: 0, target: 2 },
      { source: 0, target: 3 },
      { source: 0, target: 4 },
      { source: 1, target: 2 },
      { source: 3, target: 4 },
    ];

    let pulseOffset = 0;

    const render = () => {
      ctx.clearRect(0, 0, width, height);
      pulseOffset += 0.03;

      // Draw Connection Beams with Flowing Pulse Dots
      links.forEach((l) => {
        const n1 = nodes[l.source];
        const n2 = nodes[l.target];

        ctx.beginPath();
        ctx.moveTo(n1.x, n1.y);
        ctx.lineTo(n2.x, n2.y);
        ctx.strokeStyle = 'rgba(0, 240, 255, 0.2)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Flowing Neural Pulse Dot
        const pulseX = n1.x + (n2.x - n1.x) * ((Math.sin(pulseOffset) + 1) / 2);
        const pulseY = n1.y + (n2.y - n1.y) * ((Math.sin(pulseOffset) + 1) / 2);

        ctx.beginPath();
        ctx.arc(pulseX, pulseY, 3, 0, Math.PI * 2);
        ctx.fillStyle = '#00f0ff';
        ctx.shadowColor = '#00f0ff';
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // Draw Nodes
      nodes.forEach((n) => {
        // Node Glow Ring
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r + 4, 0, Math.PI * 2);
        ctx.fillStyle = `${n.color}33`;
        ctx.fill();

        // Node Body
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = n.color;
        ctx.fill();

        // Text Label
        ctx.font = '10px JetBrains Mono';
        ctx.fillStyle = '#f1f5f9';
        ctx.textAlign = 'center';
        ctx.fillText(n.label, n.x, n.y + n.r + 14);
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [recon]);

  return (
    <motion.div
      whileHover={{ y: -4 }}
      className="glass-card p-6 rounded-3xl border border-white/10 flex flex-col justify-between space-y-4 font-sans"
    >
      <div className="flex items-center justify-between font-mono border-b border-white/10 pb-3">
        <div className="flex items-center space-x-2">
          <div className="p-2 rounded-xl bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan shadow-glow-cyan">
            <Network className="w-4 h-4" />
          </div>
          <h3 className="font-bold text-slate-100 font-display text-sm">Recon Neural Network Topology</h3>
        </div>
        <span className="text-[10px] font-mono text-cyber-cyan">5 CONNECTED NODES</span>
      </div>

      <div className="relative w-full h-[230px] bg-black/40 rounded-2xl border border-white/10 overflow-hidden">
        <canvas ref={canvasRef} className="w-full h-full" />
      </div>
    </motion.div>
  );
};

