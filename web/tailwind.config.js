/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        accent: { DEFAULT: "#175CD3", hover: "#1849A9", soft: "#EFF4FF" },
        ink: { 900: "#101828", 700: "#344054", 500: "#667085", 300: "#98A2B3", 100: "#F2F4F7" },
        line: "#E4E7EC",
        canvas: "#F9FAFB",
        sev: { critical: "#B42318", high: "#D92D20", medium: "#DC6803", low: "#039855", info: "#667085" },
      },
      borderRadius: { DEFAULT: "8px", sm: "6px" },
      fontSize: {
        "2xs": ["11px", { lineHeight: "16px" }],
        xs: ["12px", { lineHeight: "17px" }],
        sm: ["13px", { lineHeight: "19px" }],
        base: ["14px", { lineHeight: "21px" }],
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      transitionDuration: { DEFAULT: "150ms" },
      boxShadow: { card: "0 1px 2px rgba(16,24,40,0.04)" },
    },
  },
  plugins: [],
};
