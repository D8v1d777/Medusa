import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { Dashboard } from "./pages/Dashboard";
import { NewEngagement } from "./pages/NewEngagement";
import { ScanControl } from "./pages/ScanControl";
import { Findings } from "./pages/Findings";
import { FindingDetail } from "./pages/FindingDetail";
import { AttackChains } from "./pages/AttackChains";
import { BlueTeam } from "./pages/BlueTeam";
import { Reports } from "./pages/Reports";
import { Settings } from "./pages/Settings";

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-900 text-gray-100">
        <aside className="w-56 bg-gray-800 p-4 flex flex-col">
          <h1 className="text-xl font-bold mb-6">Medusa</h1>
          <nav className="space-y-1">
            <NavLink to="/" className="block py-2 px-3 rounded hover:bg-gray-700" end>Dashboard</NavLink>
            <NavLink to="/new" className="block py-2 px-3 rounded hover:bg-gray-700">New Engagement</NavLink>
            <NavLink to="/scan" className="block py-2 px-3 rounded hover:bg-gray-700">Scan Control</NavLink>
            <NavLink to="/findings" className="block py-2 px-3 rounded hover:bg-gray-700">Findings</NavLink>
            <NavLink to="/chains" className="block py-2 px-3 rounded hover:bg-gray-700">Attack Chains</NavLink>
            <NavLink to="/blueteam" className="block py-2 px-3 rounded hover:bg-gray-700">Blue Team</NavLink>
            <NavLink to="/reports" className="block py-2 px-3 rounded hover:bg-gray-700">Reports</NavLink>
            <NavLink to="/settings" className="block py-2 px-3 rounded hover:bg-gray-700">Settings</NavLink>
          </nav>
        </aside>
        <main className="flex-1 overflow-auto p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/new" element={<NewEngagement />} />
            <Route path="/scan" element={<ScanControl />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/finding/:id" element={<FindingDetail />} />
            <Route path="/chains" element={<AttackChains />} />
            <Route path="/blueteam" element={<BlueTeam />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
