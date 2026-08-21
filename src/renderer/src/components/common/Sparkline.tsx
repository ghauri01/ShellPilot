interface SparklineProps {
  data: number[]
  max?: number
  color?: string
  fill?: boolean
  height?: number
}

export function Sparkline({
  data,
  max,
  color = 'var(--accent)',
  fill = true,
  height = 44
}: SparklineProps): React.JSX.Element {
  const w = 100
  const h = 100
  const peak = max ?? Math.max(1, ...data)
  const step = data.length > 1 ? w / (data.length - 1) : w
  const pts = data.map((v, i) => `${(i * step).toFixed(2)},${(h - (v / peak) * h).toFixed(2)}`)
  const line = `M${pts.join(' L')}`
  const area = `${line} L${w},${h} L0,${h} Z`
  return (
    <svg
      className="spark"
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      style={{ height }}
    >
      {fill && <path d={area} fill={color} opacity={0.12} />}
      <path d={line} fill="none" stroke={color} strokeWidth={1.6} vectorEffect="non-scaling-stroke" />
    </svg>
  )
}
