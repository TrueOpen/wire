// Command verify-dispatch-schema checks the generated-code-free signing tables
// against the descriptor consumers compile. It reuses the canonical verifier.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/TrueOpen/wire/dispatch"
)

func main() {
	image := flag.String("image", "../build/image.json", "Buf JSON descriptor image")
	flag.Parse()
	data, err := os.ReadFile(*image)
	if err == nil {
		err = dispatch.ValidateDescriptorImage(data)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("canonical dispatch tables match the descriptor")
}
