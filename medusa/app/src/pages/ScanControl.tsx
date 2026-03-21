export function ScanControl() {
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Scan Control</h1>
      <div className="flex gap-4">
        <div className="w-48 bg-gray-800 rounded p-4">
          <h3>Module Queue</h3>
          <p className="text-gray-400 text-sm mt-2">Header Analyzer: Complete</p>
          <p className="text-gray-400 text-sm">Crawler: Waiting</p>
        </div>
        <div className="flex-1 bg-gray-800 rounded p-4">
          <h3>Live Terminal</h3>
          <pre className="mt-2 h-64 overflow-auto font-mono text-sm bg-black p-2 rounded">
            [WebSocket stream would appear here]
          </pre>
        </div>
        <div className="w-72 bg-gray-800 rounded p-4">
          <h3>Live Findings</h3>
          <p className="text-gray-400 text-sm mt-2">No findings yet</p>
          <div className="mt-4 flex gap-2">
            <button className="px-3 py-1 bg-yellow-600 rounded text-sm">Pause</button>
            <button className="px-3 py-1 bg-red-600 rounded text-sm">Stop</button>
          </div>
        </div>
      </div>
    </div>
  );
}
