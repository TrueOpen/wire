// Command verify-import-boundaries enforces the descriptor import direction that
// the module split makes this repository's structural rule.
//
// Two claims are checked, both against the transitive descriptor closure rather
// than the import lines of a single file:
//
//   - shared.v1 is an import leaf. It may not reach any other package this
//     repository owns, directly or through anything it imports.
//   - task.v1 and bus.v1 do not reach hub.v1, directly or
//     transitively.
//
// Reading only the import lines would miss the case that matters. An import
// three files deep is still an import: it still puts the imported package in the
// generated code's dependency graph, still makes the two Go packages a cycle
// candidate, and still forces a consumer of the leaf to pull the module it was
// supposed to be free of. The rule is about the closure, so the check is too.
//
// This exists for the same reason tools/verify-rest-encoding does. A direction
// that only a document asserts is not a contract: the next person to add
// `import "hub/v1/common.proto"` to a task file gets a clean build and
// discovers the cycle later, in a downstream repository, as a compile error with
// no explanation attached. Here it is one failing step naming the exact chain.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/TrueOpen/wire/tools/internal/protoimage"
)

// ownedPrefixes are the descriptor path prefixes this repository owns. Anything
// else in a closure - google/, cosmos/, gogoproto/ - is a third-party dependency
// and is not what the direction rule is about.
var ownedPrefixes = []string{"shared/", "hub/", "task/", "bus/"}

// rule is one direction claim: files under From must not reach anything under
// any of Forbidden.
type rule struct {
	name      string
	from      string
	forbidden []string
	why       string
}

var rules = []rule{
	{
		name:      "shared.v1 is an import leaf",
		from:      "shared/",
		forbidden: []string{"hub/", "task/", "bus/"},
		why: "a shared package that imports a domain package is not shared: every consumer of the " +
			"shared symbols inherits the domain it was supposed to be independent of",
	},
	{
		name:      "task.v1 does not reach hub.v1",
		from:      "task/",
		forbidden: []string{"hub/"},
		why:       "Task owns the evidence wire, which requires Task to stop depending on Hub",
	},
	{
		name:      "bus.v1 does not reach hub.v1",
		from:      "bus/",
		forbidden: []string{"hub/"},
		why:       "the envelope is transport and must not carry a Hub type, or every Bus consumer links the Hub module",
	},
}

func main() {
	imagePath := flag.String("image", "../build/image.json", "buf JSON descriptor image")
	flag.Parse()

	if err := run(*imagePath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(imagePath string) error {
	image, err := protoimage.Load(imagePath)
	if err != nil {
		return err
	}

	deps := make(map[string][]string, len(image.File))
	present := make(map[string]bool, len(image.File))
	for _, file := range image.File {
		deps[file.Name] = file.Dependency
		present[file.Name] = true
	}

	var problems []string
	checked := 0
	for _, current := range rules {
		roots := ownedFilesUnder(deps, current.from)
		if len(roots) == 0 {
			// A rule whose subject has vanished is a silently passing rule, which is
			// worse than a failing one: the guarantee disappears with no signal.
			problems = append(problems, fmt.Sprintf("%s: no descriptor files under %q, so the rule checked nothing",
				current.name, current.from))
			continue
		}
		checked += len(roots)
		for _, root := range roots {
			for _, chain := range violations(deps, present, root, current.forbidden) {
				problems = append(problems, fmt.Sprintf("%s: %s\n    %s\n    %s",
					current.name, strings.Join(chain, " -> "), current.why,
					"remove the import or move the symbol into shared/v1"))
			}
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("descriptor import direction violated:\n\n%s", strings.Join(problems, "\n\n"))
	}
	fmt.Printf("verified %d descriptor import direction rule(s) over %d owned file(s)\n", len(rules), checked)
	return nil
}

func ownedFilesUnder(deps map[string][]string, prefix string) []string {
	var out []string
	for name := range deps {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// violations reports one shortest chain per forbidden file reached from root, so
// the failure names the path that has to be cut rather than only its endpoint.
// A chain is reported once per endpoint; a package reached by several routes
// would otherwise produce one message per route and bury the one that matters.
func violations(deps map[string][]string, present map[string]bool, root string, forbidden []string) [][]string {
	type step struct {
		name string
		path []string
	}
	seen := map[string]bool{root: true}
	queue := []step{{name: root, path: []string{root}}}
	reported := map[string]bool{}
	var out [][]string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, dep := range deps[current.name] {
			if seen[dep] {
				continue
			}
			seen[dep] = true
			path := append(append([]string{}, current.path...), dep)
			if hasAnyPrefix(dep, forbidden) && !reported[dep] {
				reported[dep] = true
				out = append(out, path)
				continue
			}
			// Only owned files are walked through. A third-party descriptor cannot
			// import this repository, so following it would cost time and could only
			// ever find nothing.
			if present[dep] && hasAnyPrefix(dep, ownedPrefixes) {
				queue = append(queue, step{name: dep, path: path})
			}
		}
	}
	return out
}

func hasAnyPrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
