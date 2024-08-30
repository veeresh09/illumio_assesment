package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func readLookupTable(filename string) (map[int]map[string]string, error) {
	lookUpTable := make(map[int]map[string]string)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		parts := strings.Split(line, ",")

		if len(parts) != 3 {
			fmt.Println("invalid format for entry found")
		}
		port := strings.TrimSpace(parts[0])
		if port == "dstport" {
			continue
		}
		portInt, err := strconv.Atoi(port)
		if err != nil {
			fmt.Println("Error converting port to integer: ", err, "entry is ", port)
			continue
		}
		protocol := strings.TrimSpace(parts[1])
		tag := strings.TrimSpace(parts[2])
		_, found := lookUpTable[portInt]
		if !found {
			lookUpTable[portInt] = make(map[string]string)
		}
		lookUpTable[portInt][protocol] = tag
	}
	return lookUpTable, nil
}

func processFlowLogs(filename string, lookupTable map[int]map[string]string) (map[string]int, map[int]map[string]int, error) {
	tagCounts := make(map[string]int)
	portAndProtocolCounts := make(map[int]map[string]int)
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 8 {
			fmt.Println("Invalid log flow format found")
			continue
		}

		dstPort := parts[5]
		dstPortNum, err := strconv.Atoi(dstPort)
		if err != nil {
			fmt.Println("Invalid prot Number in the log flow entry found")
			continue
		}
		protocolNumber := parts[7]
		var protocol string
		if protocolNumber == "6" {
			protocol = "tcp"
		} else if protocolNumber == "17" {
			protocol = "udp"
		} else {
			protocol = "unknown"
		}

		tag, found := lookupTable[dstPortNum][protocol]
		if !found {
			fmt.Println(dstPortNum, protocolNumber)
			tag = "Untagged"
		}
		tagCounts[tag]++
		_, found = portAndProtocolCounts[dstPortNum]
		if !found {
			portAndProtocolCounts[dstPortNum] = make(map[string]int)
		}
		portAndProtocolCounts[dstPortNum][protocol]++
	}
	return tagCounts, portAndProtocolCounts, nil
}
func main() {
	lookupTable, err := readLookupTable("lookup_table.txt")
	if err != nil {
		fmt.Println("error reading lookup table", err)
		return
	}

	tagCounts, portNProtocolCounts, err := processFlowLogs("log_files.txt", lookupTable)

	if err != nil {
		fmt.Println("error processing the log files", err)
		return
	}

	file, err := os.Create("tag_counts.txt")

	if err != nil {
		fmt.Println("error creating new file", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for key, count := range tagCounts {
		_, err := fmt.Fprintf(writer, "%s,%d\n", key, count)
		if err != nil {
			return
		}
	}
	err = writer.Flush()
	if err != nil {
		return
	}

	protocolFile, err := os.Create("port_protocol_counts.txt")
	if err != nil {
		fmt.Println("error creating new file", err)
		return
	}
	defer protocolFile.Close()

	writer = bufio.NewWriter(protocolFile)

	for port, protocolMap := range portNProtocolCounts {
		for protocol, count := range protocolMap {
			_, err := fmt.Fprintf(writer, "%d,%s,%d\n", port, protocol, count)
			if err != nil {
				return
			}
		}
	}
	err = writer.Flush()
	if err != nil {
		return
	}

}
