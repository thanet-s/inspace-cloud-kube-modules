// inspace-discovery is intentionally read-only. It has no code path that opts
// in to Client mutations.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider-inspace/pkg/inspace"
)

type report struct {
	Locations []inspace.Location `json:"locations"`
	Location  string             `json:"location,omitempty"`
	HostPools []inspace.HostPool `json:"hostPools,omitempty"`
	VMCount   *int               `json:"vmCount,omitempty"`
}

func main() {
	baseURL := flag.String("base-url", "https://api.inspace.cloud", "InSpace API base URL")
	location := flag.String("location", "", "location slug to inspect")
	smoke := flag.Bool("smoke", false, "also perform a read-only VM list request")
	flag.Parse()
	apiKey := os.Getenv("INSPACE_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "INSPACE_API_KEY is required")
		os.Exit(2)
	}
	client, err := inspace.NewClient(inspace.Options{BaseURL: *baseURL, APIKey: apiKey})
	if err != nil {
		fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	locations, err := client.ListLocations(ctx)
	if err != nil {
		fail(err)
	}
	result := report{Locations: locations, Location: *location}
	if result.Location == "" {
		for _, item := range locations {
			if item.IsDefault {
				result.Location = item.Slug
				break
			}
		}
	}
	if result.Location != "" {
		result.HostPools, err = client.ListHostPools(ctx, result.Location)
		if err != nil {
			fail(err)
		}
		if *smoke {
			vms, listErr := client.ListVMs(ctx, result.Location)
			if listErr != nil {
				fail(listErr)
			}
			count := len(vms)
			result.VMCount = &count
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
