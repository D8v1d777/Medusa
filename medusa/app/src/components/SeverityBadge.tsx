import { severityColor } from "../lib/severity";

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`px-2 py-0.5 rounded text-xs text-white ${severityColor(severity)}`}
    >
      {severity}
    </span>
  );
}
