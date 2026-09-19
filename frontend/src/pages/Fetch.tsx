import Playground from '../components/Playground'
import { fetchUrl } from '../api/client'

export default function Fetch() {
  return (
    <Playground
      title="Fetch"
      description="Preview a link. (SSRF sink — the server would fetch whatever URL you provide.)"
      fields={[{ name: 'url', label: 'URL', placeholder: 'https://example.com' }]}
      samples={[
        { label: 'metadata', values: { url: 'http://169.254.169.254/latest/meta-data/' } },
        { label: 'file://', values: { url: 'file:///etc/passwd' } },
      ]}
      submitLabel="Preview"
      onSubmit={(v) => fetchUrl(v.url)}
    />
  )
}
