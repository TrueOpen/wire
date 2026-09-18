// Command verify-amino enforces the legacy Amino identity required by the
// Phase 0 Web3 EIP-712 path. The signing projection reads the descriptor option,
// so an absent or locally invented name would produce a different digest.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/TrueOpen/wire/tools/internal/protoimage"
)

var msgServices = map[string]string{
	"hub.v1.Msg":  "trueopen/x/hub/",
	"task.v1.Msg": "trueopen/x/task/",
}

func main() {
	imagePath := flag.String("image", "../build/image.json", "buf JSON descriptor image")
	flag.Parse()

	count, err := verify(*imagePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("verified %d public Msg amino name(s)\n", count)
}

func verify(imagePath string) (int, error) {
	image, err := protoimage.Load(imagePath)
	if err != nil {
		return 0, err
	}
	index := protoimage.NewIndex(image)
	seen := map[string]string{}
	seenServices := map[string]bool{}
	var problems []string
	count := 0

	for _, file := range image.File {
		for _, service := range file.Service {
			serviceName := file.Package + "." + service.Name
			prefix, checked := msgServices[serviceName]
			if !checked {
				continue
			}
			seenServices[serviceName] = true
			for _, method := range service.Method {
				input, ok := index.Message(method.InputType)
				if !ok {
					problems = append(problems, fmt.Sprintf("%s.%s: input %s is missing from the descriptor",
						serviceName, method.Name, method.InputType))
					continue
				}
				want := prefix + strings.TrimPrefix(method.InputType, "."+file.Package+".")
				got := input.AminoName()
				switch {
				case got == "":
					problems = append(problems, fmt.Sprintf("%s.%s: %s has no amino.name; want %q",
						serviceName, method.Name, method.InputType, want))
				case got != want:
					problems = append(problems, fmt.Sprintf("%s.%s: %s amino.name=%q; want %q",
						serviceName, method.Name, method.InputType, got, want))
				case seen[got] != "":
					problems = append(problems, fmt.Sprintf("%s.%s: amino.name %q duplicates %s",
						serviceName, method.Name, got, seen[got]))
				default:
					seen[got] = serviceName + "." + method.Name
					count++
				}
			}
		}
	}

	for serviceName := range msgServices {
		if !seenServices[serviceName] {
			problems = append(problems, fmt.Sprintf("%s is missing, so its amino contract checked nothing", serviceName))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return 0, fmt.Errorf("public Msg amino contract violated:\n  %s", strings.Join(problems, "\n  "))
	}
	return count, nil
}
