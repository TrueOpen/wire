// Command verify-dispatch-schema checks signing tables and pagination scope
// assets against the descriptor consumers compile.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/TrueOpen/wire/dispatch"
)

func main() {
	image := flag.String("image", "../build/image.json", "Buf JSON descriptor image")
	registry := flag.String("registry", "../registry/v1/domains.json", "Canonical domain registry")
	fixture := flag.String("query-fixture", "../testdata/v1/shared/query_page_v1.json", "Pagination scope vectors")
	flag.Parse()
	data, err := os.ReadFile(*image)
	if err == nil {
		err = dispatch.ValidateDescriptorImage(data)
	}
	if err == nil {
		var domains, vectors []byte
		domains, err = os.ReadFile(*registry)
		if err == nil {
			vectors, err = os.ReadFile(*fixture)
		}
		if err == nil {
			err = validateQueryPageScopes(data, domains, vectors)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("canonical dispatch tables and pagination scopes match the descriptor")
}
