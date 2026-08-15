package main

import (
	"html/template"
	"strings"
)

// iconHTML renders an inline Lucide SVG (path data in the generated
// lucideIcons map in icons_gen.go) so the site needs no icon font, icon JS or
// CDN — every byte the browser loads comes from this origin.
//
// style is the inline style for the glyph; the .lucide CSS class sizes it to
// the surrounding font-size and stroke uses currentColor so it takes the
// inherited color. name and style are author-controlled template constants,
// never user input.
func iconHTML(name, style string) template.HTML {
	inner, ok := lucideIcons[name]
	if !ok {
		return template.HTML("<!-- missing icon: " + template.HTMLEscapeString(name) + " -->")
	}
	var b strings.Builder
	b.WriteString(`<svg class="lucide lucide-`)
	b.WriteString(name)
	b.WriteString(`"`)
	if style != "" {
		b.WriteString(` style="`)
		b.WriteString(style)
		b.WriteString(`"`)
	}
	b.WriteString(` xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">`)
	b.WriteString(inner)
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}
