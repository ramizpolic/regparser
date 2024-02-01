package main

import (
	"fmt"
	"os"
	"path"
	"windows-regparser"
)

const (
	registryFilePath = "/home/ramiz-polic/Documents/win10/SOFTWARE"
)

func main() {
	// open file as a reader
	regFile, err := os.Open(registryFilePath)
	if err != nil {
		fmt.Printf("fatal error: %v", err)
		os.Exit(1)
	}

	registry, err := regparser.NewRegistry(regFile)
	if err != nil {
		fmt.Println("error happened", err)
		os.Exit(1)
	}

	// list all keys from these paths
	listPaths(registry, []string{
		//"Microsoft/Windows NT/CurrentVersion",                                 // platform, needs filter
		"Microsoft/Windows/CurrentVersion/Component Based Servicing/Packages", // installed kbs, needs filter and comparator
		//"Microsoft/Windows NT/CurrentVersion/ProfileList",                     // user profiles, needed for per-user reader
		//"Microsoft/Windows/CurrentVersion/Uninstall",                          // installed apps
		//"Wow6432Node/Microsoft/Windows/CurrentVersion/Uninstall",              // installed apps
	})
}

func listKeysFromPath(registry *regparser.Registry, keyPath string) {
	key := registry.OpenKey(keyPath)
	if key == nil {
		return
	}

	for _, subkey := range key.Subkeys() {
		fmt.Printf("%-120s\n", path.Join(keyPath, subkey.Name()))
	}

	// print all keys under this path
	for _, value := range key.Values() {
		// THIS CAN BE UNICODE/UTF-16 VALUE!!!
		fmt.Printf("%-120s : %#v\n", path.Join(keyPath, value.ValueName()), value.ValueData().String)
	}
}

func listPaths(registry *regparser.Registry, keys []string) {
	for _, key := range keys {
		listKeysFromPath(registry, key)
	}
}
