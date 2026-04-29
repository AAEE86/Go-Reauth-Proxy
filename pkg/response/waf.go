package response

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

type WAFBlockPageOptions struct {
	Status  int
	TraceID string
}

const (
	wafBlockedTitle   = "Request blocked"
	wafBlockedMessage = "Access denied by security policy."
)

const wafBlockedContent = `
{{define "content"}}
<div class="text-center px-5 max-w-md">
	<img src="/android-chrome-512x512.png" alt="Logo" style="width:64px;height:64px;margin:0 auto 1.25rem;display:block;border-radius:16px;">
	<h1 class="text-4xl font-semibold tracking-tight mb-4">{{.Title}}</h1>
	<p class="text-lg text-gray-600 mb-8">{{.Message}}</p>
	<div style="margin:0 auto 2rem;max-width:28rem;text-align:left;border:1px solid #e5e7eb;padding:1rem 1.25rem;background:#fafafa;">
		<div style="font-size:.75rem;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.6rem;">Trace ID</div>
		<code style="font-size:.875rem;color:#111;word-break:break-all;">{{.RequestPath}}</code>
	</div>
	<div class="mt-12">
		{{template "footer" .}}
	</div>
</div>
{{end}}
`

var wafBlockedTmpl = template.Must(
	template.New("base").
		Parse(baseTemplate + footerTemplate + wafBlockedContent),
)

func WAFBlocked(w http.ResponseWriter, r *http.Request, opts WAFBlockPageOptions) {
	status := opts.Status
	if status < 400 || status > 599 {
		status = http.StatusForbidden
	}
	w.Header().Set("X-Fn-Knock-WAF-Blocked", "1")
	w.Header().Set("X-Fn-Knock-WAF-Trace-ID", opts.TraceID)
	w.Header().Set("Cache-Control", "no-store")

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(struct {
			Success bool   `json:"success"`
			Code    string `json:"code"`
			Message string `json:"message"`
			TraceID string `json:"trace_id"`
		}{
			Success: false,
			Code:    "WAF_BLOCKED",
			Message: "Request blocked by WAF",
			TraceID: opts.TraceID,
		})
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	data := buildPageData(r, nil)
	data.Title = wafBlockedTitle
	data.Message = wafBlockedMessage
	data.RequestPath = opts.TraceID
	if data.RequestPath == "" {
		data.RequestPath = strconv.Itoa(status)
	}
	_ = wafBlockedTmpl.ExecuteTemplate(w, "layout", data)
}

func wantsJSON(r *http.Request) bool {
	if r == nil {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}
