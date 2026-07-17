/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,ts,tsx,md,mdx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: '#08090B',
          1: '#0C0D10',
          2: '#101113',
          3: '#16181B',
          4: '#1B1E22',
        },
        bone: {
          DEFAULT: '#EDE7D8',
          mute: '#9B9789',
          dim: '#6B675C',
          deep: '#3E3B35',
        },
        wire: {
          DEFAULT: 'rgba(237, 231, 216, 0.08)',
          hi: 'rgba(237, 231, 216, 0.16)',
          lo: 'rgba(237, 231, 216, 0.04)',
        },
        signal: {
          DEFAULT: '#33E8C8',
          dim: '#1F8C77',
          glow: 'rgba(51, 232, 200, 0.20)',
        },
        warn: {
          DEFAULT: '#FF6B3D',
          dim: '#A14224',
        },
      },
      fontFamily: {
        display: ['"Instrument Serif"', 'Iowan Old Style', 'Georgia', 'serif'],
        sans: ['"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      letterSpacing: {
        spec: '0.22em',
        meta: '0.16em',
      },
      maxWidth: {
        content: '78rem',
        prose: '38rem',
      },
      keyframes: {
        blink: {
          '0%, 49%': { opacity: '1' },
          '50%, 100%': { opacity: '0.15' },
        },
        scan: {
          '0%':   { transform: 'translateY(0%)',   opacity: '0' },
          '5%':   { opacity: '0.8' },
          '95%':  { opacity: '0.8' },
          '100%': { transform: 'translateY(100%)', opacity: '0' },
        },
        ticker: {
          '0%, 18%':   { opacity: '0', transform: 'translateY(6px)' },
          '20%, 80%':  { opacity: '1', transform: 'translateY(0)' },
          '82%, 100%': { opacity: '0', transform: 'translateY(-6px)' },
        },
        pulse_dot: {
          '0%, 100%': { transform: 'scale(1)',   opacity: '1' },
          '50%':      { transform: 'scale(1.4)', opacity: '0.4' },
        },
        ur_advance: {
          '0%':   { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
        rise: {
          '0%':   { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        blink:      'blink 1.1s steps(2) infinite',
        scan:       'scan 4s linear infinite',
        pulse_dot:  'pulse_dot 1.6s ease-in-out infinite',
        ur_advance: 'ur_advance 6s cubic-bezier(.4,0,.2,1) infinite',
        rise:       'rise 0.8s cubic-bezier(.2,.7,.2,1) both',
      },
    },
  },
  plugins: [],
};
