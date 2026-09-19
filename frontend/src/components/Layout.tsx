import { NavLink, Outlet } from 'react-router'

const endpoints = [
  { to: '/login', label: 'Login (SQLi)' },
  { to: '/ping', label: 'Ping (Command)' },
  { to: '/files', label: 'Files (Traversal)' },
  { to: '/greet', label: 'Greet (SSTI)' },
  { to: '/fetch', label: 'Fetch (SSRF)' },
  { to: '/track', label: 'Track (Log4Shell)' },
]

export default function Layout() {
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">Injection Range</div>
        <span className="badge">semgate test range</span>
        <nav className="nav">
          <NavLink to="/" end>Home</NavLink>
          <NavLink to="/hints">Hints</NavLink>
          <div className="sys">Endpoints</div>
          {endpoints.map((e) => (
            <NavLink key={e.to} to={e.to}>{e.label}</NavLink>
          ))}
        </nav>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  )
}
