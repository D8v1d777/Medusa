import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { SeverityBadge } from "../components/SeverityBadge";

export function Findings() {
  const [findings, setFindings] = useState<any[]>([]);
  useEffect(() => {
    api<{ findings: any[] }>("/api/findings?limit=100").then((r) => setFindings(r.findings || [])).catch(() => setFindings([]));
  }, []);
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Findings</h1>
      <div className="flex gap-2 mb-4">
        <input className="flex-1 p-2 bg-gray-800 rounded" placeholder="Search" />
        <button className="px-4 py-2 bg-gray-600 rounded">Export CSV</button>
      </div>
      <div className="bg-gray-800 rounded overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="text-left">
              <th className="p-2">Severity</th>
              <th className="p-2">Title</th>
              <th className="p-2">Target</th>
              <th className="p-2">Module</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} className="border-t border-gray-700">
                <td className="p-2"><SeverityBadge severity={f.severity} /></td>
                <td className="p-2">
                  <Link to={`/finding/${f.id}`} className="text-blue-400 hover:underline">
                    {f.title}
                  </Link>
                </td>
                <td className="p-2 truncate max-w-xs">{f.target}</td>
                <td className="p-2">{f.module}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
