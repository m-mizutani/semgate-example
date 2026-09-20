package http

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/m-mizutani/semgate-example/pkg/domain/model"
	"github.com/m-mizutani/semgate-example/pkg/usecase"
	"github.com/m-mizutani/semgate-example/pkg/utils/logging"
)

// envelope is the common response shape for every /api endpoint. The verdict
// fields are empty when the attack did not fire.
type envelope struct {
	Endpoint  string `json:"endpoint"`
	Exploited bool   `json:"exploited"`
	Category  string `json:"category"`
	RuleID    string `json:"rule_id"`
	Detail    string `json:"detail"`
	Message   string `json:"message"`
	Result    any    `json:"result"`
}

// loginRequest is the POST body for the SQLi endpoint.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	// r.Body is already wrapped with a 1KB MaxBytesReader by boundInputs. Read
	// the whole body so trailing data past a small valid JSON object still
	// counts toward the limit, and reject any trailing content.
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "request body exceeds 1KB limit")
			return
		}
		writeError(w, r, http.StatusBadRequest, "could not read request body")
		return
	}
	var req loginRequest
	if err := json.Unmarshal(data, &req); err != nil {
		// json.Unmarshal also rejects trailing content after the JSON object.
		writeError(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}

	res := h.sim.Login(r.Context(), req.Username, req.Password)
	msg := "invalid username or password"
	if res.Verdict.Fired {
		msg = "SQL injection succeeded — authentication bypassed and the users table was dumped"
	}
	respond(w, r, "login", res.Verdict, msg, loginResultBody(res),
		slog.Group("input", "username", req.Username, "password", req.Password),
		"body")
}

func (h *handlers) ping(w http.ResponseWriter, r *http.Request) {
	host, ok := queryParam(w, r, "host")
	if !ok {
		return
	}
	res := h.sim.Ping(r.Context(), host)
	msg := "ping completed"
	if res.Verdict.Fired {
		msg = "OS command injection succeeded — an extra command ran on the host"
	}
	respond(w, r, "ping", res.Verdict, msg, map[string]any{"output": res.Output},
		slog.Group("input", "host", host), "query")
}

func (h *handlers) files(w http.ResponseWriter, r *http.Request) {
	reqPath, ok := queryParam(w, r, "path")
	if !ok {
		return
	}
	res := h.sim.ReadFile(r.Context(), reqPath)
	msg := "file not found"
	if res.Found && !res.Verdict.Fired {
		msg = "file served"
	}
	if res.Verdict.Fired {
		msg = "path traversal succeeded — a file outside the web root was disclosed"
	}
	respond(w, r, "files", res.Verdict, msg,
		map[string]any{"path": res.Path, "found": res.Found, "content": res.Content},
		slog.Group("input", "path", reqPath), "query")
}

func (h *handlers) greet(w http.ResponseWriter, r *http.Request) {
	name, ok := queryParam(w, r, "name")
	if !ok {
		return
	}
	res := h.sim.Greet(r.Context(), name)
	msg := "greeting rendered"
	if res.Verdict.Fired {
		msg = "template injection succeeded — the injected expression was evaluated"
	}
	respond(w, r, "greet", res.Verdict, msg, map[string]any{"rendered": res.Rendered},
		slog.Group("input", "name", name), "query")
}

func (h *handlers) fetch(w http.ResponseWriter, r *http.Request) {
	rawURL, ok := queryParam(w, r, "url")
	if !ok {
		return
	}
	res := h.sim.Fetch(r.Context(), rawURL)
	msg := "URL preview fetched"
	if res.Verdict.Fired {
		msg = "SSRF succeeded — an internal address was reached"
	}
	respond(w, r, "fetch", res.Verdict, msg,
		map[string]any{"target": res.Target, "body": res.Body},
		slog.Group("input", "url", rawURL), "query")
}

func (h *handlers) track(w http.ResponseWriter, r *http.Request) {
	logTag := r.Header.Get("X-Log-Tag")
	if logTag == "" {
		writeError(w, r, http.StatusBadRequest, "missing required header: X-Log-Tag")
		return
	}
	// Length is bounded by boundInputs middleware.
	res := h.sim.Track(r.Context(), logTag)
	msg := "request recorded"
	if res.Verdict.Fired {
		msg = "Log4Shell succeeded — the logged value expanded to a JNDI lookup"
	}
	respond(w, r, "track", res.Verdict, msg, map[string]any{"logged": res.Logged},
		slog.Group("input", "x_log_tag", logTag), "header")
}

// loginResultBody shapes the login result for JSON, hiding the leaked users on
// a benign response.
func loginResultBody(res usecase.LoginResult) map[string]any {
	users := make([]map[string]any, 0, len(res.Users))
	for _, u := range res.Users {
		users = append(users, map[string]any{
			"id": u.ID, "username": u.Username,
			"password_hash": u.PasswordHash, "email": u.Email,
		})
	}
	body := map[string]any{"authenticated": res.Authenticated}
	if res.Verdict.Fired {
		body["users"] = users
	} else {
		body["users"] = nil
	}
	return body
}

// queryParam reads a required query parameter, enforcing the size bound. It
// writes the error response and returns ok=false when the parameter is missing
// or too large.
func queryParam(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	if !r.URL.Query().Has(name) {
		writeError(w, r, http.StatusBadRequest, "missing required query parameter: "+name)
		return "", false
	}
	// Length is bounded by the boundInputs middleware.
	return r.URL.Query().Get(name), true
}

// respond writes the response envelope and emits the structured detection log.
func respond(w http.ResponseWriter, r *http.Request, endpoint string, v model.Verdict, message string, result any, input slog.Attr, location string) {
	env := envelope{
		Endpoint:  endpoint,
		Exploited: v.Fired,
		Category:  string(v.Category),
		RuleID:    v.RuleID,
		Detail:    v.Detail,
		Message:   message,
		Result:    result,
	}

	level := slog.LevelInfo
	if v.Fired {
		level = slog.LevelWarn
	}
	logging.From(r.Context()).LogAttrs(r.Context(), level, "detection",
		slog.String("endpoint", endpoint),
		slog.Bool("exploited", v.Fired),
		slog.String("category", string(v.Category)),
		slog.String("rule_id", v.RuleID),
		slog.String("detail", v.Detail),
		slog.String("payload_location", location),
		slog.Int("status", http.StatusOK),
		// input names the value the verdict was made on; requestAttrs carries
		// the whole request that value was taken from.
		input,
		requestAttrs(r),
	)

	writeJSON(w, http.StatusOK, env)
}

// writeError writes an error envelope and logs the rejection.
func writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	logging.From(r.Context()).Warn("request_rejected",
		"status", status, "message", message, "path", r.URL.Path)
	writeJSON(w, status, map[string]any{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
