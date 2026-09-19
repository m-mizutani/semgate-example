import Playground from '../components/Playground'
import { greet } from '../api/client'

export default function Greet() {
  return (
    <Playground
      title="Greet"
      description="Generate a greeting message. (Template injection sink — the name is rendered through a template engine.)"
      fields={[{ name: 'name', label: 'Name', placeholder: 'Alice' }]}
      samples={[
        { label: '{{7*7}}', values: { name: '{{7*7}}' } },
        { label: '${(2+3)*4}', values: { name: '${(2+3)*4}' } },
      ]}
      submitLabel="Greet"
      onSubmit={(v) => greet(v.name)}
    />
  )
}
