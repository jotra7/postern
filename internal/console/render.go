package console

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"time"
)

// html/template, never text/template, and never string concatenation.
//
// Host names, service names, group names, provider console URLs and error
// text all reach these pages, and some of them do not originate on this
// machine: an error string can carry whatever a hub or a remote host put in a
// response, and the inventory is a hand-edited file whose fields nothing
// constrains to a safe character set. text/template would render every one of
// them as markup. html/template escapes per context — element text, attribute
// value, URL, script — which is the property this file exists to keep, and
// TestConsole_Render_EscapesAHostNameContainingHTML is what holds it.
//
//go:embed templates/*.html
var templateFS embed.FS

//go:embed assets/*
var assetFS embed.FS

var templates = template.Must(template.New("console").Funcs(template.FuncMap{
	"duration": func(d time.Duration) string { return d.Round(time.Second).String() },
	"yesno":    func(b bool) string { return map[bool]string{true: "yes", false: "no"}[b] },
}).ParseFS(templateFS, "templates/*.html"))

// Page is the whole template context, and it is the only thing a template
// ever sees.
//
// Nothing reachable from here is key material: Keyring.State returns a name,
// a path and a deadline, and never an identity.Signer, so there is no field a
// rendering mistake could print a private key from. That is a property of the
// types rather than of this struct's field list —  see Keyring's doc comment.
type Page struct {
	Title string
	// CSRF is the per-process token, rendered into every form. A hostile page
	// cannot read it: the same-origin policy stops it reading this response
	// body at all.
	CSRF string
	// Slots is what the key panel shows.
	Slots []SlotState
	// Flash is the last action's result, or nil.
	Flash *Flash
	// Fleet is the fleet view; Host is set on a host page.
	Fleet FleetView
	Host  *HostView
	// Plan is set on the deploy page.
	Plan *DeployPlan
	// ReturnTo is the path a form's redirect comes back to.
	ReturnTo string
	// DisarmHint is the CLI command for the one operation this console does
	// not perform. Rendered as text, never as a form.
	DisarmHint string
	// Nav is which top-level page this is, so the header can mark it current.
	Nav string
	// SignerUnlocked is the signer slot's state, read by the deploy page to
	// say what a signing run is waiting on.
	SignerUnlocked bool
}

func (s *Server) page(title string, fleet FleetView, host *HostView) Page {
	p := Page{
		Title:      title,
		CSRF:       s.guard.token,
		Slots:      s.keys.State(),
		Flash:      s.takeFlash(),
		Fleet:      fleet,
		Host:       host,
		ReturnTo:   "/",
		DisarmHint: "postern disarm <host>",
		Nav:        "fleet",
	}
	if title == "deploy" {
		p.Nav = "deploy"
	}
	for i := range p.Slots {
		// A locked slot knows no path, because Keyring only records the file a
		// key actually came from. The unlock form still has one to name, and
		// which file it would open is worth saying before it is typed into:
		// a signer slot with no --sign-key is a locked row that no passphrase
		// will ever open. The path is not secret; the console prints it once
		// the slot is unlocked anyway.
		if p.Slots[i].KeyFile == "" {
			if path, err := s.keyPath(p.Slots[i].Slot); err == nil {
				p.Slots[i].KeyFile = path
			}
		}
		if p.Slots[i].Slot == SlotSigner {
			p.SignerUnlocked = p.Slots[i].Unlocked
		}
	}
	if host != nil {
		p.ReturnTo = "/host/" + host.Name
	}
	return p
}

// render writes one template. It renders into a buffer first so a template
// error produces an error page rather than a half-written page with a 200
// already committed.
func (s *Server) render(w http.ResponseWriter, name string, data Page) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "console: render "+name+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A page that can knock a fleet has no business in anyone's frame, and
	// nothing here loads anything from anywhere: every asset is embedded and
	// served from this origin.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(buf.Bytes())
}

// asset is one embedded file, read once at startup.
type asset struct {
	body        []byte
	contentType string
}

// assets is the complete set of files this console will ever serve, keyed by
// the exact name a request may ask for.
//
// A closed set rather than a lookup into the embedded filesystem, and the
// difference matters even though embed.FS has no parent directory to escape
// into: nothing here ever passes a request-derived string to a file read, so
// the request cannot influence which bytes are served or their declared
// content type. Both are fixed here, at startup, from names this file
// controls.
var assets = map[string]asset{
	"console.css": {body: mustAsset("assets/console.css"), contentType: "text/css; charset=utf-8"},
	"console.js":  {body: mustAsset("assets/console.js"), contentType: "text/javascript; charset=utf-8"},
}

func mustAsset(name string) []byte {
	data, err := assetFS.ReadFile(name)
	if err != nil {
		panic("console: embedded asset " + name + ": " + err.Error())
	}
	return data
}

// handleAsset serves one of the two embedded files, or 404s.
func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	a, ok := assets[r.PathValue("file")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(a.body)
}
