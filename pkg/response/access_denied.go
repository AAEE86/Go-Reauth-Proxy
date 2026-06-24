package response

import (
	"go-reauth-proxy/pkg/i18n"
	"html/template"
	"net/http"
)

const accessDeniedContent = `
{{define "content"}}
<div class="text-center px-5 max-w-2xl">
	<img src="/__assets__/favicon/android-chrome-512x512.png" alt="Logo" style="width:64px;height:64px;margin:0 auto 1.25rem;display:block;border-radius:16px;">
	<h1 class="text-4xl font-semibold tracking-tight mb-4">{{.Title}}</h1>
	<p class="text-lg text-gray-600 mb-8">{{.Message}}</p>
	<div style="margin:0 auto 2rem;max-width:32rem;text-align:left;border:1px solid #e5e7eb;padding:1rem 1.25rem;background:#fafafa;">
		<div style="font-size:.75rem;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.9rem;">{{index .Labels "request"}}</div>
		<div style="display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;margin-bottom:.75rem;">
			<span style="color:#6b7280;">{{index .Labels "host"}}</span>
			<code style="font-size:.875rem;color:#111;word-break:break-all;text-align:right;">{{if .RequestHost}}{{.RequestHost}}{{else}}-{{end}}</code>
		</div>
		<div style="display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;">
			<span style="color:#6b7280;">{{index .Labels "path"}}</span>
			<code style="font-size:.875rem;color:#111;word-break:break-all;text-align:right;">{{if .RequestPath}}{{.RequestPath}}{{else}}-{{end}}</code>
		</div>
	</div>
	<div class="flex justify-center gap-3">
		<a href="/__auth__/api/auth/logout"
		   class="inline-block px-5 py-2.5 text-sm font-medium text-white bg-black hover:bg-gray-900 transition-colors duration-150 border border-black">
			{{index .Labels "logout"}}
		</a>
	</div>
	<div class="mt-12">
		{{template "footer" .}}
	</div>
</div>
{{end}}
`

var accessDeniedTmpl = template.Must(
	template.New("base").
		Parse(baseTemplate + footerTemplate + accessDeniedContent),
)

func AccessDenied(w http.ResponseWriter, r *http.Request) {
	locale := i18n.ResolveRequestLocale(r)
	w.Header().Set("X-Fn-Knock-Access-Denied", "scope")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Language", locale)

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		var stack [512]byte
		_, _ = w.Write(appendAccessDeniedJSON(stack[:0], i18n.T(locale, "gateway.accessDeniedJson")))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	data := buildPageData(r, nil)
	data.Title = i18n.T(locale, "gateway.accessDeniedTitle")
	data.Message = i18n.T(locale, "gateway.accessDeniedMessage")
	_ = accessDeniedTmpl.ExecuteTemplate(w, "layout", data)
}

func appendAccessDeniedJSON(buf []byte, message string) []byte {
	if cap(buf) == 0 {
		buf = make([]byte, 0, len(message)+80)
	}
	buf = append(buf, `{"success":false,"code":"ACCESS_DENIED","message":`...)
	buf = appendJSONString(buf, message)
	buf = append(buf, "}\n"...)
	return buf
}
