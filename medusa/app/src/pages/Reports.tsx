export function Reports() {
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Reports</h1>
      <div className="flex gap-2 mb-4">
        <button className="px-4 py-2 bg-gray-600 rounded">Executive Summary</button>
        <button className="px-4 py-2 bg-gray-600 rounded">Technical Report</button>
        <button className="px-4 py-2 bg-green-600 rounded">Generate</button>
      </div>
      <div className="bg-gray-800 rounded p-4 min-h-64">
        <p className="text-gray-400">Report preview will appear here.</p>
      </div>
    </div>
  );
}
