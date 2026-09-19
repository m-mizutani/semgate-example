import Playground from '../components/Playground'
import { ping } from '../api/client'

export default function Ping() {
  return (
    <Playground
      title="Ping"
      description="Network reachability check. (OS command injection sink — the host is concatenated into a shell command.)"
      fields={[{ name: 'host', label: 'Host', placeholder: 'example.com' }]}
      samples={[
        { label: '; cat /etc/passwd', values: { host: 'example.com; cat /etc/passwd' } },
        { label: '$(whoami)', values: { host: '$(whoami)' } },
      ]}
      submitLabel="Ping"
      onSubmit={(v) => ping(v.host)}
    />
  )
}
