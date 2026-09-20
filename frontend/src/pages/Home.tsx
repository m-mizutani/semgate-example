import { Link } from 'react-router'

const endpoints = [
  { to: '/login', title: 'Login', vuln: 'SQL injection' },
  { to: '/ping', title: 'Ping', vuln: 'OS command injection' },
  { to: '/files', title: 'Files', vuln: 'Path traversal' },
  { to: '/greet', title: 'Greet', vuln: 'Template injection (SSTI)' },
  { to: '/fetch', title: 'Fetch', vuln: 'SSRF' },
  { to: '/track', title: 'Track', vuln: 'Log4Shell (JNDI)' },
]

export default function Home() {
  return (
    <div>
      <div className="hero">
        <div className="headline">Six classic injections. Zero guards. Everything lands.</div>
        <div className="subline">Point <code>semgate</code> at it and watch them stop.</div>
      </div>

      <div className="disclaimer" role="note">
        <strong>Heads up.</strong> This is an intentionally vulnerable site, built on purpose to be
        attacked so the <code>semgate</code> guard can be validated against it.
        <ul>
          <li>Every value shown is synthetic — no real credentials, secrets, hosts, or files.</li>
          <li>Nothing is actually executed: no database, no shell, no filesystem. Inputs are
            parsed and evaluated only to decide whether an attack would fire.</li>
          <li>Every request you send here is logged (input, headers, source) as structured data
            for inspection. When the <code>semgate</code> guard is enabled, each request is also
            sent to the TypeSafe API to be judged — minus its credential headers.</li>
          <li>Do not deploy this on a public network, and never enter real credentials.</li>
          <li>For authorized security testing only.</li>
        </ul>
      </div>

      <h2>Endpoints</h2>
      <div className="grid">
        {endpoints.map((e) => (
          <Link key={e.to} to={e.to} className="card" style={{ display: 'block' }}>
            <h3>{e.title}</h3>
            <p>{e.vuln}</p>
          </Link>
        ))}
      </div>

      <p className="lead" style={{ marginTop: '1.2rem' }}>
        New here? The <Link to="/hints">Hints</Link> page lists every injection point and a payload
        that lands with no guard in place.
      </p>
    </div>
  )
}
