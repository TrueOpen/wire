package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/TrueOpen/wire/tools/internal/protoimage"
)

func validateQueryPageScopes(image, registry, fixture []byte) error {
	expected, err := queryPageSelectors(image)
	if err != nil {
		return err
	}
	if err = validateQueryPageRegistry(registry, expected); err != nil {
		return err
	}
	return validateQueryPageVectors(fixture, expected)
}

func queryPageSelectors(raw []byte) (map[string][]string, error) {
	var image protoimage.Image
	if err := json.Unmarshal(raw, &image); err != nil {
		return nil, err
	}
	index := protoimage.NewIndex(&image)
	expected := map[string][]string{}
	for _, file := range image.File {
		if file.Package != "hub.v1" && file.Package != "task.v1" {
			continue
		}
		for _, service := range file.Service {
			if service.Name != "Query" {
				continue
			}
			for _, method := range service.Method {
				request, exists := index.Message(method.InputType)
				if !exists {
					return nil, fmt.Errorf("query request %s is missing", method.InputType)
				}
				fields := append([]protoimage.Field(nil), request.Field...)
				sort.Slice(fields, func(i, j int) bool { return fields[i].Number < fields[j].Number })
				paged := false
				var names []string
				for _, field := range fields {
					if field.TypeName == ".shared.v1.QueryPageRequestV1" {
						paged = true
					} else {
						names = append(names, field.Name)
					}
				}
				if paged {
					expected["/"+file.Package+".Query/"+method.Name] = names
				}
			}
		}
	}
	return expected, nil
}

func validateQueryPageRegistry(registry []byte, expected map[string][]string) error {
	var domains struct {
		Domains []struct {
			Domain   string `json:"domain"`
			Variants []struct {
				Key    string   `json:"key"`
				Fields []string `json:"fields"`
			} `json:"variants"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(registry, &domains); err != nil {
		return err
	}
	registered := map[string]bool{}
	for _, domain := range domains.Domains {
		if domain.Domain != "TRUEOPEN_QUERY_SELECTOR_V1" {
			continue
		}
		for _, variant := range domain.Variants {
			fields, exists := expected[variant.Key]
			if !exists || registered[variant.Key] || !reflect.DeepEqual(fields, variant.Fields) {
				return fmt.Errorf("query selector registry differs from descriptor for %s", variant.Key)
			}
			registered[variant.Key] = true
		}
	}
	for rpc := range expected {
		if !registered[rpc] {
			return fmt.Errorf("paginated query %s has no registered selector", rpc)
		}
	}
	return nil
}

func validateQueryPageVectors(fixture []byte, expected map[string][]string) error {
	var vectors struct {
		Vectors []struct {
			Domain  string `json:"domain"`
			RPC     string `json:"rpc_method"`
			Variant string `json:"variant"`
			Fields  []struct {
				Name string `json:"name"`
			} `json:"fields"`
			Replay []struct {
				Name  string `json:"name"`
				Field int    `json:"field"`
				Value string `json:"value"`
			} `json:"replay"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(fixture, &vectors); err != nil {
		return err
	}
	coverage := map[string]bool{}
	for _, vector := range vectors.Vectors {
		fields, exists := expected[vector.RPC]
		if !exists {
			return fmt.Errorf("query fixture names an unregistered RPC %s", vector.RPC)
		}
		key := vector.Domain + vector.RPC
		if coverage[key] {
			return fmt.Errorf("duplicate query scope vector %s", vector.RPC)
		}
		coverage[key] = true
		want := []string{"rpc_method"}
		switch vector.Domain {
		case "TRUEOPEN_QUERY_RPC_V1":
		case "TRUEOPEN_QUERY_SELECTOR_V1":
			if vector.Variant != vector.RPC {
				return fmt.Errorf("query fixture variant differs from RPC %s", vector.RPC)
			}
			want = append([]string{"chain_id", "rpc_method_digest"}, fields...)
			chainReplay, rpcReplay := false, false
			for _, replay := range vector.Replay {
				chainReplay = chainReplay || replay.Field == 0 && replay.Name == "cross_chain"
				other, registered := expected[replay.Value]
				rpcReplay = rpcReplay || replay.Field == 1 && strings.HasPrefix(replay.Name, "cross_rpc") && registered && replay.Value != vector.RPC && len(other) == len(fields)
			}
			if !chainReplay {
				return fmt.Errorf("query selector %s lacks cross-chain replay", vector.RPC)
			}
			for rpc, other := range expected {
				if rpc != vector.RPC && len(other) == len(fields) && !rpcReplay {
					return fmt.Errorf("query selector %s lacks same-arity cross-RPC replay", vector.RPC)
				}
			}
		default:
			return fmt.Errorf("unexpected query fixture domain %s", vector.Domain)
		}
		got := make([]string, len(vector.Fields))
		for i, field := range vector.Fields {
			got[i] = field.Name
		}
		if !reflect.DeepEqual(want, got) {
			return fmt.Errorf("query fixture selector order differs from descriptor for %s", vector.RPC)
		}
	}
	for rpc := range expected {
		for _, domain := range []string{"TRUEOPEN_QUERY_RPC_V1", "TRUEOPEN_QUERY_SELECTOR_V1"} {
			if !coverage[domain+rpc] {
				return fmt.Errorf("paginated query %s lacks its %s vector", rpc, domain)
			}
		}
	}
	return nil
}
