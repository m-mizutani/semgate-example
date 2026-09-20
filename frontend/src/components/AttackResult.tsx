import { BlockedError, type Envelope, type RequestError } from '../api/client'

interface Props {
  envelope: Envelope | null
  error: RequestError | null
}

// percent formats a 0..1 probability for the block banner.
function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`
}

// AttackResult renders the five outcome states: blocked by the guard, fired,
// benign, request rejected, and nothing yet.
export default function AttackResult({ envelope, error }: Props) {
  // A blocked request is not a failed one: the guard stopped it on purpose, so
  // it gets its own banner rather than the generic rejection banner.
  if (error instanceof BlockedError) {
    return (
      <div className="banner blocked" role="alert">
        🛡 Blocked by semgate — {error.category}
        <span className="sub">
          The guard judged this request to be an attack and answered 403. The vulnerable
          handler never ran, so the payload was never fed to the sink it targets.
        </span>
        <p className="tag">
          Attack probability: {percent(error.probability)} · category confidence:{' '}
          {percent(error.confidence)}
        </p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="banner warn" role="alert">
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
