import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";

export function NewEngagement() {
  const [step, setStep] = useState(1);
  const [name, setName] = useState("");
  const [operator, setOperator] = useState("");
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [scopeIps, setScopeIps] = useState("");
  const [scopeDomains, setScopeDomains] = useState("");
  const navigate = useNavigate();

  const finish = async () => {
    const body = {
      name: name || "New Engagement",
      operator: operator || "Analyst",
      target,
      scope_ips: scopeIps.split(/[\n,]/).map((s) => s.trim()).filter(Boolean),
      scope_domains: scopeDomains.split(/[\n,]/).map((s) => s.trim()).filter(Boolean),
      scope_cidrs: [],
    };
    const { id } = await api<{ id: string }>("/api/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    navigate(`/scan?session=${id}`);
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">New Engagement</h1>
      <div className="max-w-xl space-y-6">
        {step === 1 && (
          <>
            <h2>Step 1: Engagement Details</h2>
            <input
              className="w-full p-2 bg-gray-800 rounded"
              placeholder="Engagement Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <input
              className="w-full p-2 bg-gray-800 rounded"
              placeholder="Operator Name"
              value={operator}
              onChange={(e) => setOperator(e.target.value)}
            />
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
              I confirm written authorization is on file
            </label>
            <button
              className="px-4 py-2 bg-blue-600 rounded disabled:opacity-50"
              disabled={!authorized}
              onClick={() => setStep(2)}
            >
              Next
            </button>
          </>
        )}
        {step === 2 && (
          <>
            <h2>Step 2: Scope</h2>
            <input
              className="w-full p-2 bg-gray-800 rounded"
              placeholder="Target URL or IP"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
            <textarea
              className="w-full p-2 bg-gray-800 rounded"
              placeholder="IP ranges (one per line)"
              value={scopeIps}
              onChange={(e) => setScopeIps(e.target.value)}
            />
            <textarea
              className="w-full p-2 bg-gray-800 rounded"
              placeholder="Domains (one per line)"
              value={scopeDomains}
              onChange={(e) => setScopeDomains(e.target.value)}
            />
            <div className="flex gap-2">
              <button className="px-4 py-2 bg-gray-600 rounded" onClick={() => setStep(1)}>Back</button>
              <button className="px-4 py-2 bg-blue-600 rounded" onClick={() => setStep(3)}>Next</button>
            </div>
          </>
        )}
        {step === 3 && (
          <>
            <h2>Step 3: Module Selection</h2>
            <p className="text-gray-400">Web, Network, Blue Team modules enabled by default.</p>
            <div className="flex gap-2">
              <button className="px-4 py-2 bg-gray-600 rounded" onClick={() => setStep(2)}>Back</button>
              <button className="px-4 py-2 bg-blue-600 rounded" onClick={() => setStep(4)}>Next</button>
            </div>
          </>
        )}
        {step === 4 && (
          <>
            <h2>Step 4: AI Configuration</h2>
            <p className="text-gray-400">Provider: OpenAI (configure in Settings)</p>
            <div className="flex gap-2">
              <button className="px-4 py-2 bg-gray-600 rounded" onClick={() => setStep(3)}>Back</button>
              <button className="px-4 py-2 bg-green-600 rounded" onClick={finish}>Finish</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
