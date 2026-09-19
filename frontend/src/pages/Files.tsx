import Playground from '../components/Playground'
import { files } from '../api/client'

export default function Files() {
  return (
    <Playground
      title="Files"
      description="View a document from the public folder. (Path traversal sink — the path is joined onto the web root without containment.)"
      fields={[{ name: 'path', label: 'Path', placeholder: 'report.txt' }]}
      samples={[
        { label: '../../../etc/passwd', values: { path: '../../../etc/passwd' } },
        { label: 'url-encoded', values: { path: '%2e%2e%2f%2e%2e%2fetc%2fpasswd' } },
      ]}
      submitLabel="Open"
      onSubmit={(v) => files(v.path)}
    />
  )
}
