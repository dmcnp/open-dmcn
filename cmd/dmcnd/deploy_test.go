package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestServiceTemplateCoversSettings keeps deploy/dmcnd.env and deploy/dmcnd.service in step with
// the variables the daemon actually reads. The daemon does not warn about a variable it does not
// know, so a misspelt or retired name in the template would be silently ignored on every host
// installed from it; and a setting missing from the template is one an operator never learns of.
func TestServiceTemplateCoversSettings(t *testing.T) {
	read := map[string]bool{}
	literal := regexp.MustCompile(`"(DMCND_[A-Z0-9_]+)"`)
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range sources {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range literal.FindAllSubmatch(b, -1) {
			read[string(m[1])] = true
		}
	}
	if len(read) == 0 {
		t.Fatal("found no DMCND_ variables in the daemon's source; the scan is broken")
	}

	documented := map[string]string{}
	// A setting line in the env file, commented out or not: `DMCND_X=` or `#DMCND_X=`.
	envLine := regexp.MustCompile(`(?m)^#?(DMCND_[A-Z0-9_]+)=`)
	unitLine := regexp.MustCompile(`(?m)^Environment=(DMCND_[A-Z0-9_]+)=`)
	for file, re := range map[string]*regexp.Regexp{
		"../../deploy/dmcnd.env":     envLine,
		"../../deploy/dmcnd.service": unitLine,
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllSubmatch(b, -1) {
			name := string(m[1])
			if prev, ok := documented[name]; ok {
				t.Errorf("%s is set in both %s and %s; one place only", name, prev, file)
			}
			documented[name] = file
		}
	}

	var missing, unknown []string
	for v := range read {
		if _, ok := documented[v]; !ok {
			missing = append(missing, v)
		}
	}
	for v := range documented {
		if !read[v] {
			unknown = append(unknown, v)
		}
	}
	sort.Strings(missing)
	sort.Strings(unknown)
	for _, v := range missing {
		t.Errorf("%s is read by dmcnd but appears in neither deploy/dmcnd.env nor deploy/dmcnd.service", v)
	}
	for _, v := range unknown {
		t.Errorf("%s is in %s but dmcnd never reads it", v, documented[v])
	}
}
