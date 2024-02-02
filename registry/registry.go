package registry

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"www.velocidex.com/golang/regparser"
)

type Registry struct {
	registry *regparser.Registry
}

func newReader(path string) (*Registry, error) {
	regFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open registry file: %w", err)
	}

	registry, err := regparser.NewRegistry(regFile)
	if err != nil {
		return nil, fmt.Errorf("cannot create registry reader: %w", err)
	}

	return &Registry{
		registry: registry,
	}, nil
}

func (r *Registry) GetPlatform() (map[string]string, error) {
	keyData, err := r.getKeyValues("Microsoft/Windows NT/CurrentVersion")
	if err != nil {
		return nil, err
	}

	osData := map[string]string{
		"type":    "operating-system",
		"os_type": "windows",
	}
	for key, value := range keyData {
		switch key {
		case "DigitalProductId", "DigitalProductId4":
			continue
		default:
			osData[key] = value
		}
	}

	return osData, nil
}

func (r *Registry) GetUpdates() (map[string]string, error) {
	keyData := r.registry.OpenKey("Microsoft/Windows/CurrentVersion/Component Based Servicing/Packages")
	if keyData == nil {
		return nil, fmt.Errorf("key not found")
	}

	// to remove:
	// update_install_clients := map[string]struct{}{"WindowsUpdateAgent": {}, "UpdateAgentLCU": {}}
	updateKeys := map[string]*regparser.CM_KEY_NODE{}
	for _, subKey := range keyData.Subkeys() {
		for _, subKeyVal := range subKey.Values() {
			if subKeyVal.Name().Value == "InstallClient" {
				updateKeys[subKey.Name()] = subKey
			}
		}
	}

	installedKbs := make(map[string]string)
	for _, subKey := range updateKeys {
		for _, val := range subKey.Values() {
			kb := ""

			if val.Name().Value == "InstallLocation" {
				re, err := regexp.Compile("KB[0-9]{7,}")
				if err != nil {
					continue
				}

				match := re.FindString(val.ValueData().String)
				if match != "" {
					kb = match
				}
			}

			if val.Name().Value == "CurrentState" && val.ValueData().String == "112" {
				re, err := regexp.Compile("KB[0-9]{7,}")
				if err != nil {
					continue
				}

				match := re.FindString(subKey.Name())
				if match != "" {
					kb = match
				}
			}

			if kb != "" {
				installedKbs[kb] = kb
			}
		}
	}

	return installedKbs, nil
}

func (r *Registry) GetAll() map[string]interface{} {
	osData, _ := r.GetPlatform()
	updateData, _ := r.GetUpdates()
	return map[string]interface{}{
		"platform": osData,
		"kbs":      updateData,
	}
}

func (r *Registry) getKeyValues(keyPath string) (map[string]string, error) {
	key := r.registry.OpenKey(keyPath)
	if key == nil {
		return nil, fmt.Errorf("key %s not found", keyPath)
	}

	data := make(map[string]string)
	for _, value := range key.Values() {
		data[value.ValueName()] = toString(value.ValueData())
	}

	return data, nil
}

func toString(data *regparser.ValueData) string {
	switch data.Type {
	case regparser.REG_SZ, regparser.REG_EXPAND_SZ:
		return strings.TrimRightFunc(data.String, func(r rune) bool {
			return r == 0 // remove null terminator
		})

	case regparser.REG_MULTI_SZ:
		return strings.Join(data.MultiSz, " ")

	case regparser.REG_DWORD, regparser.REG_DWORD_BIG_ENDIAN, regparser.REG_QWORD:
		return strconv.FormatUint(data.Uint64, 10)

	case regparser.REG_BINARY:
		// Return as hex to preserve buffer; we don't really care about this value
		return fmt.Sprintf("%X", data.Data)

	case
		regparser.REG_LINK,                       // Unicode symbolic link
		regparser.REG_RESOURCE_LIST,              // device-driver resource list
		regparser.REG_FULL_RESOURCE_DESCRIPTOR,   // hardware setting
		regparser.REG_RESOURCE_REQUIREMENTS_LIST, // hardware resource list
		regparser.REG_UNKNOWN:                    // unhandled
		fallthrough

	default:
		return ""
	}
}
