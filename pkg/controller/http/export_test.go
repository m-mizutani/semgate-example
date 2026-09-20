package http

import "io"

var WithClock = withClock

// RecordBody exposes the request body recorder captureRequest installs. It
// returns the body to read through and a function reading back what the log
// record would show: the recorded content and its status.
func RecordBody(src io.ReadCloser, limit int) (io.ReadCloser, func() (string, string)) {
	recorder := &bodyRecorder{src: src, limit: limit}
	return recorder, func() (string, string) {
		body := recorder.snapshot()
		return body.content, body.status
	}
}
