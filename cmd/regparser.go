package main

import (
	"fmt"
	"os"
	"path"
	"windows-regparser"
)

const (
	registryFilePath = "/Users/rpolic/Desktop/repos/regparser/testdata/NTUSER.DAT"
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

	// recursively list all keys
	recurseListMany(registry, []string{
		"Software/Microsoft/Windows NT/CurrentVersion",
	})
}

func recursiveList(registry *regparser.Registry, keyName string) {
	key := registry.OpenKey(keyName)
	if key == nil {
		fmt.Printf("---- %s NOT FOUND!", keyName)
		return
	}

	fmt.Printf("\n ==== %s Subkeys:\n\n", keyName)
	for _, subkey := range key.Subkeys() {
		fmt.Printf(" %s - %v\n", subkey.Name(), subkey.LastWriteTime())

		recursiveList(registry, path.Join(keyName, subkey.Name()))
	}

	fmt.Printf("\n ==== %s Values:\n\n", keyName)
	for _, value := range key.Values() {
		fmt.Printf(" %s : %#v\n", value.ValueName(), value.ValueData())
	}
}

func recurseListMany(registry *regparser.Registry, keys []string) {
	for _, key := range keys {
		recursiveList(registry, key)
	}
}
