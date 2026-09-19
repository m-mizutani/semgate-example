import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import AttackResult from './AttackResult'
import { RequestError, type Envelope } from '../api/client'

const firedEnvelope: Envelope = {
  endpoint: 'login',
  exploited: true,
  category: 'sqli',
  rule_id: 'sqli_result_altered',
  detail: 'concatenated query returned 3 rows vs 0 for the safe query',
  message: 'SQL injection succeeded',
  result: { authenticated: true, users: [{ username: 'admin' }] },
}

const benignEnvelope: Envelope = {
  endpoint: 'login',
  exploited: false,
  category: '',
  rule_id: '',
  detail: '',
  message: 'invalid username or password',
  result: { authenticated: false, users: null },
}

describe('AttackResult', () => {
  it('shows the attack-landed banner when fired', () => {
    render(<AttackResult envelope={firedEnvelope} error={null} />)
    expect(screen.getByRole('alert')).toHaveTextContent('Attack landed')
    expect(screen.getByText(/sqli_result_altered/)).toBeInTheDocument()
    expect(screen.getByText(/"admin"/)).toBeInTheDocument()
  })

  it('shows a benign response when not fired', () => {
    render(<AttackResult envelope={benignEnvelope} error={null} />)
    expect(screen.getByRole('status')).toHaveTextContent('Benign response')
  })

  it('shows an error banner for a rejected request', () => {
    render(<AttackResult envelope={null} error={new RequestError(413, 'Input is too large')} />)
    expect(screen.getByRole('alert')).toHaveTextContent('413')
  })

  it('shows a rate-limited request as a warning', () => {
    render(<AttackResult envelope={null} error={new RequestError(429, 'Too many requests')} />)
    expect(screen.getByRole('alert')).toHaveTextContent('429')
    expect(screen.getByRole('alert')).toHaveClass('warn')
  })

  it('renders nothing before the first submit', () => {
    const { container } = render(<AttackResult envelope={null} error={null} />)
    expect(container).toBeEmptyDOMElement()
  })
})
