import { useState } from 'react'
import { type Envelope, RequestError } from '../api/client'
import AttackResult from './AttackResult'

export interface Field {
  name: string
  label: string
  placeholder?: string
  type?: 'text' | 'password'
}

export interface Sample {
  label: string
  values: Record<string, string>
}

interface Props {
  title: string
  description: string
  fields: Field[]
  samples?: Sample[]
  submitLabel: string
  onSubmit: (values: Record<string, string>) => Promise<Envelope>
}

export default function Playground({ title, description, fields, samples, submitLabel, onSubmit }: Props) {
  const initial = Object.fromEntries(fields.map((f) => [f.name, '']))
  const [values, setValues] = useState<Record<string, string>>(initial)
  const [envelope, setEnvelope] = useState<Envelope | null>(null)
  const [error, setError] = useState<RequestError | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setEnvelope(null)
    setError(null)
    try {
      const env = await onSubmit(values)
      setEnvelope(env)
    } catch (err) {
      if (err instanceof RequestError) {
        setError(err)
      } else {
        setError(new RequestError(0, 'Network error — could not reach the range. Try again.'))
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <h1>{title}</h1>
      <p className="lead">{description}</p>

      <form className="card" onSubmit={handleSubmit}>
        {fields.map((f) => (
          <div className="field" key={f.name}>
            <label htmlFor={f.name}>{f.label}</label>
            <input
              id={f.name}
              type={f.type ?? 'text'}
              placeholder={f.placeholder}
              value={values[f.name]}
              onChange={(e) => setValues((v) => ({ ...v, [f.name]: e.target.value }))}
            />
          </div>
        ))}

        {samples && samples.length > 0 && (
          <div className="samples">
            {samples.map((s) => (
              <button
                type="button"
                className="sample"
                key={s.label}
                onClick={() => setValues((v) => ({ ...v, ...s.values }))}
              >
                {s.label}
              </button>
            ))}
          </div>
        )}

        <div style={{ marginTop: '0.6rem' }}>
          <button type="submit" disabled={submitting}>
            {submitting ? 'Sending…' : submitLabel}
          </button>
        </div>
      </form>

      <AttackResult envelope={envelope} error={error} />
    </div>
  )
}
