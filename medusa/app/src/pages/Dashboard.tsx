import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";

export function Dashboard() {
  const [sessions, setSessions] = useState<any[]>([]);
  useEffect(() => {
    api<any[]>("/api/sessions").then(setSessions).catch(() => setSessions([]));
  }, []);
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>
      <div className="grid grid-cols-4 gap-4 mb-8">
        <div className="bg-gray-800 p-4 rounded">Active Sessions: {sessions.filter((s) => s.status === "active").length}</div>
        <div className="bg-gray-800 p-4 rounded">Total Findings: -</div>
        <div className="bg-gray-800 p-4 rounded">Critical Open: -</div>
        <div className="bg-gray-800 p-4 rounded">Verified Rate: -</div>
      </div>
      <div className="bg-gray-800 rounded p-4">
        <h2 className="font-bold mb-4">Recent Sessions</h2>
        <table className="w-full">
          <thead>
            <tr className="text-left">
              <th>Name</th>
              <th>Target</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.id}>
                <td>{s.name}</td>
                <td>{s.target || "-"}</td>
                <td>{s.status}</td>
                <td>
                  <Link to={`/scan?session=${s.id}`} className="text-blue-400">Resume</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
