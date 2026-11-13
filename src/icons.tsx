import { CSSProperties, ReactNode } from "react";

interface IconProps {
  size?: number;
  className?: string;
  style?: CSSProperties;
}

function Svg({
  size = 16,
  className = "",
  style,
  solid = false,
  children,
}: IconProps & { solid?: boolean; children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      aria-hidden="true"
      className={`${solid ? "ico-f" : "ico"} ${className}`}
      style={style}
    >
      {children}
    </svg>
  );
}

export function OsIcon({ osType, size = 20, ...rest }: { osType: string } & IconProps) {
  const os = osType.toLowerCase();
  if (os.includes("win")) {
    return (
      <Svg size={size} {...rest} solid>
        <path d="M3 5.2 10.8 4v7.4H3zm8.9-1.3L21 2.5v8.9h-9.1zM3 12.6h7.8V20L3 18.8zm8.9 0H21v8.9l-9.1-1.4z" />
      </Svg>
    );
  }
  if (os.includes("android")) {
    return (
      <Svg size={size} {...rest}>
        <path d="M5 10a7 7 0 0 1 14 0v7a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2Zm3.5-6.5L10 6m5.5-2.5L14 6M5 13.5h14" />
        <circle cx="9.5" cy="10.5" r=".8" fill="currentColor" />
        <circle cx="14.5" cy="10.5" r=".8" fill="currentColor" />
      </Svg>
    );
  }
  return (
    <Svg size={size} {...rest}>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M2 20h20M9 16v4m6-4v4" />
    </Svg>
  );
}

export const RadarIcon = (p: IconProps) => (
  <Svg size={18} {...p}>
    <circle cx="12" cy="12" r="9" />
    <circle cx="12" cy="12" r="5" />
    <circle cx="12" cy="12" r="1.2" fill="currentColor" />
    <path d="M12 12 18.4 5.6" />
  </Svg>
);

export const ShieldIcon = (p: IconProps) => (
  <Svg size={14} {...p}>
    <path d="M12 2.5 4.5 5.8v5.9c0 4.9 3.2 9.1 7.5 10.3 4.3-1.2 7.5-5.4 7.5-10.3V5.8Zm-3 9.7 2 2 4-4.2" />
  </Svg>
);

export const QrIcon = (p: IconProps) => (
  <Svg {...p}>
    <rect x="3" y="3" width="7" height="7" rx="1" />
    <rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="3" y="14" width="7" height="7" rx="1" />
    <path d="M14 14h3v3h-3z" fill="currentColor" stroke="none" />
    <path d="M19 14v3h2v4h-4v-2h-3" />
  </Svg>
);

export const FolderIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 6.5a2 2 0 0 1 2-2h4.2l2 2.2H19a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z" />
  </Svg>
);

export const CopyIcon = (p: IconProps) => (
  <Svg size={15} {...p}>
    <rect x="9" y="9" width="11" height="11" rx="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </Svg>
);

export const CheckIcon = (p: IconProps) => (
  <Svg size={15} {...p}>
    <path d="M5 12.5 9.5 17 19 7.5" />
  </Svg>
);

export const CloseIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6 6l12 12M18 6 6 18" />
  </Svg>
);

export const WarningIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 3 2.5 20h19ZM12 10v4.5" />
    <circle cx="12" cy="17.2" r=".7" fill="currentColor" />
  </Svg>
);

export const SendIcon = (p: IconProps) => (
  <Svg size={15} {...p}>
    <path d="M21 3 10 14m11-11-6.5 18-3.8-7.2L3.5 10Z" />
  </Svg>
);

export const ChevronIcon = (p: IconProps) => (
  <Svg {...p}>
    <path d="m6 15 6-6 6 6" />
  </Svg>
);
