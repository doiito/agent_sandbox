package sandbox

import (
	"net/http"
	"strings"
)

// APIErrorResponse is the v2 control API error envelope. Code is stable for
// programmatic decisions; Error is a human-readable explanation. Clients must
// handle future codes without treating them as success or replay permission.
type APIErrorResponse struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

func versionedAPIPath(path string) bool {
	return path == "/v2" || strings.HasPrefix(path, "/v2/")
}

// withHTTPRouteErrors only translates ServeMux-generated 404/405 responses.
// Registered handlers still go through ServeHTTP, which populates Pattern and
// PathValue, and receive the original writer (including upgrade/stream support).
func withHTTPRouteErrors(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, pattern := mux.Handler(r)
		if pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
		// No registered handler applies. Inspect only the internally generated
		// response, never a business handler or its potentially streaming body.
		probe := &routeErrorProbe{header: make(http.Header)}
		handler.ServeHTTP(probe, r)
		var code, explanation string
		switch probe.status {
		case http.StatusNotFound:
			code, explanation = "not_found", "route not found"
		case http.StatusMethodNotAllowed:
			code, explanation = "method_not_allowed", "method not allowed"
			if allow := probe.header.Values("Allow"); len(allow) != 0 {
				w.Header()["Allow"] = append([]string(nil), allow...)
			}
		default:
			// Canonical redirects may also have no matching pattern. Preserve
			// their status, Location and standard path/CONNECT behavior.
			mux.ServeHTTP(w, r)
			return
		}
		r.Pattern = ""
		writeObservedJobError(w, r, probe.status, code, explanation, versionedAPIPath(r.URL.Path))
	})
}

// routeErrorProbe retains only routing headers/status and discards the generated
// standard-library body. It cannot wrap or buffer an application response.
type routeErrorProbe struct {
	header http.Header
	status int
}

func (w *routeErrorProbe) Header() http.Header { return w.header }

func (w *routeErrorProbe) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *routeErrorProbe) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(data), nil
}
