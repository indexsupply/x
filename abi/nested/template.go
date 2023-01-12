package nested

import (
	"bytes"
	"go/format"
	"strings"
	"text/template"

	"github.com/indexsupply/x/abi"
)

const ct = `
{{ define "x" }}
{{ if eq .Type "tuple" }}
{{ titleize .Name }} struct {
	{{ range .Components }}
	{{ template "x" . }}
	{{ end }}
}
{{ else }}
{{ titleize .Name }} {{ .Gtype }}
{{ end }}
{{ end }}
{{ with .Event }}
type {{ titleize .Name }} struct {
	{{ range .Inputs }}
	{{ template "x" .}}
	{{ end }}
}
{{ end }}
`

var funcs = template.FuncMap{"titleize": strings.ToTitle}

func Generate() ([]byte, error) {
	data := struct {
		Event abi.Event
	}{
		Event: e,
	}
	var (
		b bytes.Buffer
		t = template.Must(template.New("abi").Funcs(funcs).Parse(ct))
	)
	if err := t.Execute(&b, data); err != nil {
		return nil, err
	}
	return format.Source(b.Bytes())
}
