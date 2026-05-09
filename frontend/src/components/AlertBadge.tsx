/** AlertBadge — status badge for alert triage states. */

interface IAlertBadgeProps {
  status: "open" | "investigating" | "closed";
}

const STATUS_STYLES: Record<string, string> = {
  open: "bg-red-900/40 text-red-400 border border-red-800",
  investigating: "bg-yellow-900/40 text-yellow-400 border border-yellow-800",
  closed: "bg-green-900/40 text-green-400 border border-green-800",
};

export default function AlertBadge({ status }: IAlertBadgeProps) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${STATUS_STYLES[status]}`}>
      {status}
    </span>
  );
}
