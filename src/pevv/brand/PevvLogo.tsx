/**
 * The PEVV padlock mark (master: pevv-logo.svg). Inline so it needs no asset loading and
 * works under the extension and desktop CSPs. `PevvBrand` shows it on every surface;
 * `fallback` is only used when a host page wants its own mark instead.
 */

export function PevvLogo({ size = 24, small = false, className }: { size?: number; small?: boolean; className?: string }) {
  return (
    <svg aria-hidden viewBox="0 0 512 512" width={size} height={size} className={className} data-testid="pevv-logo">
      <defs>
        <linearGradient id="pevvLogoBody" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#67e8f9" /><stop offset="1" stopColor="#0ea5c6" /></linearGradient>
        <linearGradient id="pevvLogoShackle" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#e879f9" /><stop offset="1" stopColor="#c44dd4" /></linearGradient>
      </defs>
      {small ? (
        <>
          <path d="M170 252V170a86 86 0 0 1 172 0v82" fill="none" stroke="#c44dd4" strokeWidth="76" strokeLinecap="round" strokeLinejoin="round" />
          <rect x="48" y="214" width="416" height="282" rx="96" fill="url(#pevvLogoBody)" />
          <ellipse cx="170" cy="336" rx="36" ry="44" fill="#0b1226" />
          <ellipse cx="342" cy="336" rx="36" ry="44" fill="#0b1226" />
          <path d="M206 408q50 48 100 0" fill="none" stroke="#0b1226" strokeWidth="30" strokeLinecap="round" strokeLinejoin="round" />
        </>
      ) : (
        <>
          <path d="M176 248V176a80 80 0 0 1 160 0v72" fill="none" stroke="url(#pevvLogoShackle)" strokeWidth="56" strokeLinecap="round" strokeLinejoin="round" />
          <rect x="80" y="224" width="352" height="256" rx="84" fill="url(#pevvLogoBody)" />
          <path d="M130 300a60 60 0 0 1 56-52" fill="none" stroke="#fff" strokeWidth="14" strokeLinecap="round" opacity=".55" />
          <ellipse cx="196" cy="340" rx="24" ry="30" fill="#0b1226" />
          <ellipse cx="316" cy="340" rx="24" ry="30" fill="#0b1226" />
          <circle cx="204" cy="328" r="9" fill="#fff" />
          <circle cx="324" cy="328" r="9" fill="#fff" />
          <ellipse cx="150" cy="392" rx="26" ry="16" fill="#f472b6" opacity=".7" />
          <ellipse cx="362" cy="392" rx="26" ry="16" fill="#f472b6" opacity=".7" />
          <path d="M232 384q24 28 48 0" fill="none" stroke="#0b1226" strokeWidth="14" strokeLinecap="round" strokeLinejoin="round" />
        </>
      )}
    </svg>
  );
}

/** The PEVV padlock. */
export function PevvBrand({ size = 24 }: { size?: number }) {
  return <PevvLogo size={size} small={size <= 32} />;
}
