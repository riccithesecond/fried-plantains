/** SeverityPill — colored severity badge for alerts and detections. */

interface ISeverityPillProps {
  severity: string;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-900/60 text-red-300 border border-red-800",
  high: "bg-orange-900/60 text-orange-300 border border-orange-800",
  medium: "bg-yellow-900/60 text-yellow-300 border border-yellow-800",
  low: "bg-blue-900/60 text-blue-300 border border-blue-800",
  info: "bg-gray-800/60 text-gray-300 border border-gray-700",
};

export default function SeverityPill({ severity }: ISeverityPillProps) {
  const style = SEVERITY_STYLES[severity.toLowerCase()] ?? SEVERITY_STYLES.info;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${style}`}>
      {severity.toUpperCase()}
    </span>
  );
}
