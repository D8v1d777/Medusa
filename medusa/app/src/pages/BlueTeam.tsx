export function BlueTeam() {
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Blue Team</h1>
      <div className="flex gap-2 mb-4">
        <button className="px-4 py-2 bg-gray-600 rounded">Detection Rules</button>
        <button className="px-4 py-2 bg-gray-600 rounded">IOC Dashboard</button>
        <button className="px-4 py-2 bg-gray-600 rounded">Hardening Report</button>
      </div>
      <div className="bg-gray-800 rounded p-4">
        <p className="text-gray-400">Select a session to view SIGMA rules, IOCs, and hardening recommendations.</p>
      </div>
    </div>
  );
}
