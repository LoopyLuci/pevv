import type { Config } from 'tailwindcss';

/** Colors resolve from the CSS variables in src/styles/globals.css (the palette's single source of truth). */
export default {
  content: ['./index.html', './desktop.html', './extension/*.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        space: {
          void: 'rgb(var(--c-space-void) / <alpha-value>)',
          deep: 'rgb(var(--c-space-deep) / <alpha-value>)',
          surface: 'rgb(var(--c-space-surface) / <alpha-value>)',
          border: 'rgb(var(--c-space-border) / <alpha-value>)',
        },
        ink: {
          primary: 'rgb(var(--c-ink-primary) / <alpha-value>)',
          secondary: 'rgb(var(--c-ink-secondary) / <alpha-value>)',
          muted: 'rgb(var(--c-ink-muted) / <alpha-value>)',
        },
        accent: {
          cyan: 'rgb(var(--c-accent-cyan) / <alpha-value>)',
          magenta: 'rgb(var(--c-accent-magenta) / <alpha-value>)',
          gold: 'rgb(var(--c-accent-gold) / <alpha-value>)',
          green: 'rgb(var(--c-accent-green) / <alpha-value>)',
          red: 'rgb(var(--c-accent-red) / <alpha-value>)',
        },
      },
      fontFamily: {
        body: ['"Inter"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config;
