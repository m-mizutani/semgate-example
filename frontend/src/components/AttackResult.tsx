import type { Envelope, RequestError } from '../api/client'

interface Props {
  envelope: Envelope | null
  error: RequestError | null
}

// AttackResult renders the four outcome states: fired, benign, input error, and
// nothing yet.
export default function AttackResult({ envelope, error }: Props) {
  if (error) {
    const cls = error.status === 413 || error.status === 400 || error.status === 429 ? 'warn' : 'ok'
    return (
      <div className={`banner ${cls}`} role="alert">
        Request rejected ({error.status})
        <span className="sub">{error.message}</span>
      </div>
    )
  }

  if (!envelope) {
    return null
  }

  if (envelope.exploited) {
    return (
      <div>
        <div className="banner exploit" role="alert">
          🎯 Attack landed — {envelope.category}
          <span className="sub">
            {envelope.message} (rule: <code>{envelope.rule_id}</code>; no guard stopped it)
          </span>
        </div>
        <p className="tag">Verdict: {envelope.detail}</p>
        <ResultBody result={envelope.result} />
      </div>
    )
  }

  return (
    <div>
      <div className="banner ok" role="status">
        Benign response
        <span className="sub">{envelope.message}</span>
      </div>
      <ResultBody result={envelope.result} />
    </div>
  )
}

function ResultBody({ result }: { result: Record<string, unknown> }) {
  return <pre>{JSON.stringify(result, null, 2)}</pre>
}
