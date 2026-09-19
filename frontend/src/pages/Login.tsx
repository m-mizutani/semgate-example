import Playground from '../components/Playground'
import { login } from '../api/client'

export default function Login() {
  return (
    <Playground
      title="Login"
      description="Sign in to the operations console. (SQL injection sink — the query is built by string concatenation.)"
      fields={[
        { name: 'username', label: 'Username', placeholder: 'alice' },
        { name: 'password', label: 'Password', placeholder: '••••••', type: 'password' },
      ]}
      samples={[
        { label: "admin' OR '1'='1", values: { username: "admin' OR '1'='1", password: 'x' } },
        { label: 'UNION SELECT', values: { username: "zzz' UNION SELECT 1, 'x'--", password: 'x' } },
      ]}
      submitLabel="Sign in"
      onSubmit={(v) => login(v.username, v.password)}
    />
  )
}
