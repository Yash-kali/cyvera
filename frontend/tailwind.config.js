/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          darkest: '#05070a',
          dark: '#070b12',
          surface: '#0b101d',
          card: '#0f1628',
          border: 'rgba(255, 255, 255, 0.08)',
          'border-glow': 'rgba(0, 240, 255, 0.3)',
          cyan: '#00f0ff',
          purple: '#7000ff',
          emerald: '#00ff9d',
          amber: '#ffb800',
          rose: '#ff2a6d',
          subtext: '#94a3b8',
        }
      },
      fontFamily: {
        display: ['Space Grotesk', 'sans-serif'],
        sans: ['Sora', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 25px -5px rgba(0, 240, 255, 0.3)',
        'glow-purple': '0 0 25px -5px rgba(112, 0, 255, 0.35)',
        'glow-emerald': '0 0 25px -5px rgba(0, 255, 157, 0.3)',
        'glow-rose': '0 0 25px -5px rgba(255, 42, 109, 0.35)',
        'glass-card': '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'cyber-gradient': 'linear-gradient(135deg, rgba(0,240,255,0.15) 0%, rgba(112,0,255,0.15) 50%, rgba(0,0,0,0) 100%)',
      },
      animation: {
        'pulse-glow': 'pulse-glow 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float': 'float 6s ease-in-out infinite',
        'spin-slow': 'spin 12s linear infinite',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { opacity: 0.6, filter: 'drop-shadow(0 0 15px rgba(0, 240, 255, 0.4))' },
          '50%': { opacity: 1, filter: 'drop-shadow(0 0 25px rgba(112, 0, 255, 0.6))' },
        },
        'float': {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-10px)' },
        }
      }
    },
  },
  plugins: [],
}

