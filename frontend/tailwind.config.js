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
        background: '#0B1020',
        sidebar: '#0F172A',
        card: '#111827',
        'card-hover': '#162032',
        surface: '#1E293B',
        border: '#1E293B',
        'border-light': '#334155',
        primary: {
          DEFAULT: '#3B82F6',
          hover: '#2563EB',
          light: '#60A5FA',
        },
        accent: {
          cyan: '#06B6D4',
          indigo: '#6366F1',
        },
        severity: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#10B981',
          info: '#3B82F6',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'monospace'],
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        fadeInUp: {
          '0%': { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        scaleIn: {
          '0%': { opacity: '0', transform: 'scale(0.96)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        pulseCritical: {
          '0%, 100%': { opacity: '1', boxShadow: '0 0 0 0 rgba(239, 68, 68, 0.45)' },
          '50%': { opacity: '0.85', boxShadow: '0 0 10px 2px rgba(239, 68, 68, 0.25)' },
        },
        scanSweep: {
          '0%': { top: '0%', opacity: '0' },
          '15%': { opacity: '0.9' },
          '85%': { opacity: '0.9' },
          '100%': { top: '100%', opacity: '0' },
        },
      },
      animation: {
        'fade-in': 'fadeIn 0.25s ease-out forwards',
        'fade-in-up': 'fadeInUp 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards',
        'scale-in': 'scaleIn 0.25s cubic-bezier(0.16, 1, 0.3, 1) forwards',
        'pulse-critical': 'pulseCritical 2.2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-sweep': 'scanSweep 2.2s ease-in-out infinite',
      }
    },
  },
  plugins: [],
}

