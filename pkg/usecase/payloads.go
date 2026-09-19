package usecase

import (
	"fmt"
	"strings"

	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

// This file holds the synthetic "leaked" payloads returned when an attack
// fires, and the benign responses returned otherwise. Everything here is
// fabricated: no real credentials, secrets, hosts, or file contents.

// leakedUsers is the fake users table an SQL injection "dumps".
func leakedUsers() []LeakedUser {
	return []LeakedUser{
		{ID: 1, Username: "admin", PasswordHash: "$2a$10$EXAMPLE0000000000000000example", Email: "admin@example.com"},
		{ID: 2, Username: "alice", PasswordHash: "$2a$10$EXAMPLE1111111111111111example", Email: "alice@example.com"},
		{ID: 3, Username: "bob", PasswordHash: "$2a$10$EXAMPLE2222222222222222example", Email: "bob@example.com"},
	}
}

// commandOutput is the fake shell output an OS command injection "runs". When
// the payload references /etc/passwd, it returns a fake passwd file; otherwise a
// fake id result.
func commandOutput(host string) string {
	if strings.Contains(host, "/etc/passwd") {
		return fakePasswd
	}
	return "uid=0(root) gid=0(root) groups=0(root)\n[synthetic output — no command was executed]"
}

// benignPing is the ordinary output of the ping tool for a normal host.
func benignPing(host string) string {
	return fmt.Sprintf("PING %s: 3 packets transmitted, 3 received, 0%% packet loss, time 2003ms", host)
}

// leakedFile is the fake content a path traversal "discloses".
func leakedFile(reqPath string) string {
	lower := strings.ToLower(reqPath)
	switch {
	case strings.Contains(lower, "passwd"):
		return fakePasswd
	case strings.Contains(lower, "shadow"):
		return "root:$6$EXAMPLE$fakehashfakehashfakehash:19000:0:99999:7:::\n[synthetic — not a real shadow file]"
	default:
		return "APP_ENV=production\nAPI_KEY=EXAMPLE-DO-NOT-USE\nDB_PASSWORD=EXAMPLE-DO-NOT-USE\n[synthetic config — no file was read]"
	}
}

// benignFile returns the content of a known sample document, or found=false for
// an unknown name.
func benignFile(reqPath string) (string, bool) {
	switch strings.TrimSpace(reqPath) {
	case "report.txt", "docs/report.txt":
		return "Quarterly report\n----------------\nAll systems nominal.", true
	case "readme.txt":
		return "Welcome to the document viewer.", true
	default:
		return "", false
	}
}

// renderedSSTI shows that the template engine evaluated the injected
// expression rather than printing it literally.
func renderedSSTI(v model.Verdict) string {
	return "Hello! [template expression was evaluated — " + v.Detail + "]"
}

// leakedMetadata is the fake cloud metadata an SSRF "reaches".
func leakedMetadata(v model.Verdict) string {
	return strings.Join([]string{
		"{",
		`  "AccessKeyId": "EXAMPLE-DO-NOT-USE",`,
		`  "SecretAccessKey": "EXAMPLE-DO-NOT-USE",`,
		`  "Token": "EXAMPLE-DO-NOT-USE",`,
		`  "note": "synthetic metadata — no request was sent (` + v.Detail + `)"`,
		"}",
	}, "\n")
}

// benignFetch is the ordinary preview of a public URL.
func benignFetch(rawURL string) string {
	return fmt.Sprintf("<title>Example Domain</title> — preview of %s [synthetic]", rawURL)
}

// jndiFired describes the JNDI lookup a Log4Shell payload triggered.
func jndiFired(v model.Verdict) string {
	return "JNDI lookup triggered — " + v.Detail + " [synthetic — no lookup was performed]"
}

// fakePasswd is a synthetic /etc/passwd used by several fired payloads.
const fakePasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
[synthetic — no file was read]`
