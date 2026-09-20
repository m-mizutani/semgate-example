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
        <div className="headline">Six classic injections. One target you are allowed to attack.</div>
        <div className="subline">
          Send a payload from your browser and see whether it lands — or whether <code>semgate</code>
          {' '}stops it first.
        </div>
      </div>

      <div className="disclaimer" role="note">
        <strong>Before you start.</strong> This site is intentionally vulnerable and exists to be
        attacked. Pick an endpoint on the left, send your payload, and the page tells you what
        happened to it.
        <ul>
          <li>Nothing you send is really executed: there is no database, no shell, and no
            filesystem behind these endpoints. Each one only decides whether your input would
            exploit the vulnerability it imitates, and every value it shows you back is
            fabricated.</li>
          <li>Three outcomes are possible. The attack lands and the endpoint reports the exploit;
            the input is treated as ordinary and you get a benign answer; or the request is
            answered <code>403</code> because the <code>semgate</code> guard judged it an attack.
            Whether a guard runs in front of the endpoints depends on how this instance was
            started, so the response is what tells you.</li>
          <li>Every request you send is logged with its input, its headers, and your source
            address. When the guard is running, the request is also sent to the TypeSafe API to be
            judged, minus the <code>Authorization</code>, <code>Proxy-Authorization</code>, and
            {' '}<code>Cookie</code> headers. Never type a real credential or anything private
            here.</li>
          <li>Requests to <code>/api</code> are rate limited per source address, so a burst is
            answered <code>429</code> with a <code>Retry-After</code> header saying how long to
            wait.</li>
          <li>The payloads listed here are for this site. Use them elsewhere only against systems
            you are authorized to test.</li>
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
