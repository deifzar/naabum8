package utils

import (
	"deifzar/naabum8/pkg/model8"
	"encoding/xml"
	"net"
)

func RemoveDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, val := range slice {
		if _, ok := seen[val]; !ok {
			seen[val] = true
			result = append(result, val)
		}
	}
	return result
}

func Difference(slice1, slice2 []string) []string {
	// Create a map to hold the elements of slice2 for easy lookup
	lookupMap := make(map[string]bool)
	for _, item := range slice2 {
		lookupMap[item] = true
	}

	// Iterate through slice1 and add elements that are not in slice2
	var result []string
	for _, item := range slice1 {
		if !lookupMap[item] {
			result = append(result, item)
		}
	}

	return result
}

func IsValidIPAddress(ip string) bool {
	ipAddress := net.ParseIP(ip)
	return ipAddress != nil
}

// Parse takes a byte array of nmap xml data and unmarshals it into an
// NmapRun struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func NmapParse(content []byte) (*model8.NmapRun, error) {
	r := &model8.NmapRun{}
	err := xml.Unmarshal(content, r)
	return r, err
}
