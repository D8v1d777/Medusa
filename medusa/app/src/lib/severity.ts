export function severityColor(s: string): string {
  const m: Record<string, string> = {
    critical: "bg-red-600",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-blue-500",
    info: "bg-gray-500",
  };
  return m[s] || "bg-gray-400";
}
