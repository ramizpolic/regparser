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
	recursiveList(registry, "")
}

func recursiveList(registry *regparser.Registry, keyName string) {
	key := registry.OpenKey(keyName)
	if key == nil {
		fmt.Printf("---- %s NOT FOUND!", keyName)
		return
	}

	for _, subkey := range key.Subkeys() {
		fmt.Printf(" [%s subkey] %s - %v\n", keyName, subkey.Name(), subkey.LastWriteTime())

		recursiveList(registry, path.Join(keyName, subkey.Name()))
	}

	//for _, value := range key.Values() {
	//	fmt.Printf(" [%s values]: %s : %#v\n", keyName, value.ValueName(), value.ValueData())
	//}
}
