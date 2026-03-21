export function CvssGauge({ score }: { score: number }) {
  const pct = Math.min(100, (score / 10) * 100);
  return (
    <div className="w-24 h-2 bg-gray-200 rounded">
      <div
        className="h-full bg-red-500 rounded"
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}
