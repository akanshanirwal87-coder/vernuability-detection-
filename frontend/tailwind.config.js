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
      }
    },
  },
  plugins: [],
}

