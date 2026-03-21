export function Settings() {
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Settings</h1>
      <div className="flex gap-2 mb-4">
        <button className="px-4 py-2 bg-gray-600 rounded">General</button>
        <button className="px-4 py-2 bg-gray-600 rounded">AI</button>
        <button className="px-4 py-2 bg-gray-600 rounded">Network</button>
        <button className="px-4 py-2 bg-gray-600 rounded">Appearance</button>
      </div>
      <div className="bg-gray-800 rounded p-4 max-w-md">
        <label className="block mb-2">API Key (stored in keychain)</label>
        <input type="password" className="w-full p-2 bg-gray-900 rounded" placeholder="••••••••" />
        <button className="mt-4 px-4 py-2 bg-blue-600 rounded">Test Connection</button>
      </div>
    </div>
  );
}
