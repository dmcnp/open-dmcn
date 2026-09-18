import { LABEL_COLORS } from '../lib/hooks/useLabels';

// The colour choices for a label. Its own module because two screens that know nothing about each
// other need it: Settings, naming a label deliberately, and the reader, making one on the spot.
export function ColorSwatches({ selected, onPick }: { selected: string; onPick: (c: string) => void }) {
  return (
    <div style={{ display: 'flex', gap: 4 }}>
      {LABEL_COLORS.map(c => (
        <button key={c} type="button" aria-label={`Color ${c}`} onClick={() => onPick(c)}
          style={{ width: 18, height: 18, borderRadius: '50%', background: c, border: selected === c ? '2px solid var(--text-strong)' : '2px solid transparent', cursor: 'pointer', padding: 0 }} />
      ))}
    </div>
  );
}
