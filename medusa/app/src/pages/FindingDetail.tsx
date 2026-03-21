import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../lib/api";
import { SeverityBadge } from "../components/SeverityBadge";
import { CvssGauge } from "../components/CvssGauge";

export function FindingDetail() {
  const { id } = useParams();
  const [finding, setFinding] = useState<any>(null);
  useEffect(() => {
    if (id) api(`/api/findings/${id}`).then(setFinding).catch(() => setFinding(null));
  }, [id]);
  if (!finding) return <p>Select a finding</p>;
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold">{finding.title}</h1>
      <SeverityBadge severity={finding.severity} />
      <CvssGauge score={finding.cvss_score || 0} />
      <p>{finding.description}</p>
      <p className="text-sm text-gray-400">Target: {finding.target}</p>
    </div>
  );
}
