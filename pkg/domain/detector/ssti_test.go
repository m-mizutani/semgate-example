package detector_test

import (
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/semgate-example/pkg/domain/detector"
	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

func TestSSTI_Inspect(t *testing.T) {
	d := detector.NewSSTI()

	testCases := map[string]struct {
		name       string
		wantFired  bool
		wantDetail string
	}{
		"benign name":             {name: "Alice", wantFired: false},
		"benign with braces text": {name: "Team {rocket}", wantFired: false},
		"jinja arithmetic":        {name: "{{7*7}}", wantFired: true, wantDetail: "49"},
		"dollar arithmetic":       {name: "${7*7}", wantFired: true, wantDetail: "49"},
		"erb arithmetic":          {name: "<%= 6*7 %>", wantFired: true, wantDetail: "42"},
		"parenthesised":           {name: "{{ (2+3)*4 }}", wantFired: true, wantDetail: "20"},
		"literal number only":     {name: "{{42}}", wantFired: false}, // evaluates to itself
		"second expression fires": {name: "{{42}}{{7*7}}", wantFired: true, wantDetail: "49"},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			v := d.Inspect(tc.name)
			wantFired(t, v.Fired, tc.wantFired)
			if tc.wantFired {
				gt.Value(t, v.Category).Equal(model.CategorySSTI)
				if tc.wantDetail != "" {
					gt.String(t, v.Detail).Contains(tc.wantDetail)
				}
			}
		})
	}
}
