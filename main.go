package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var (
	// rate limit is the number of ICMP Echo Requests we send per second
	ratelimit = 20000 // Rate limiter: 20000 per second
	// awsIpRangesUrl is the URL to download the AWS IP ranges JSON
	awsIpRangesUrl = "https://ip-ranges.amazonaws.com/ip-ranges.json"

	// map to store responding IPs
	respondingIPs = make(map[uint32]string)
	// lock to use when updating the respondingIPs map
	mutex sync.Mutex
)

// Define JSON structures
type IPRange struct {
	IPPrefix           string `json:"ip_prefix"`
	Region             string `json:"region"`
	NetworkBorderGroup string `json:"network_border_group"`
	Service            string `json:"service"`
}

type IPData struct {
	SyncToken  string    `json:"syncToken"`
	CreateDate string    `json:"createDate"`
	Prefixes   []IPRange `json:"prefixes"`
}

// fetchIPData handles the downloading and parsing of the JSON
func fetchIPData(url string) (IPData, error) {
	var data IPData

	resp, err := http.Get(url)
	if err != nil {
		return data, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, err
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return data, err
	}

	return data, nil
}

// Function to listen for ICMP Echo Replies
func listenPingForReplies() {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer conn.Close()

	packet := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFrom(packet)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		message, err := icmp.ParseMessage(1, packet[:n])
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		switch message.Type {
		case ipv4.ICMPTypeEchoReply:
			_, ok := message.Body.(*icmp.Echo)
			if !ok {
				fmt.Println("Got bad Echo Reply message")
				continue
			}

			// Add responding IP to the map
			ipInt := ipToUint32(src.String())
			mutex.Lock()
			respondingIPs[ipInt] = src.String()
			mutex.Unlock()
		}
	}
}

// Function to expand a CIDR to a list of IPs
func expandCIDR(cidrStr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

// Function to increment an IP address
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// Function to convert an IP address string to an integer
func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// Function to convert an integer to a human readable string
func humanizeNumber(num int64) string {
	if num < 0 {
		return fmt.Sprintf("-%s", humanizeNumber(-num))
	}
	if num < 1000 {
		return fmt.Sprintf("%d", num)
	}
	return fmt.Sprintf("%s,%03d", humanizeNumber(num/1000), num%1000)
}

// Function to send an ICMP Echo Request to an IP address
func sendICMPEchoRequest(ip string) {
	conn, err := net.Dial("ip4:icmp", ip)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer conn.Close()

	// ICMP Echo Request header
	header := make([]byte, 8)
	header[0] = 8                             // Echo Request type
	header[1] = 0                             // Code 0
	binary.BigEndian.PutUint16(header[6:], 1) // Identifier

	// Calculate ICMP checksum
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	sum += (sum >> 16)
	checksum := ^uint16(sum)

	binary.BigEndian.PutUint16(header[2:], checksum)

	// Send ICMP Echo Request
	_, err = conn.Write(header)
	if err != nil {
		fmt.Println("Error:", err)
	}
}

// Function to finalize the program and write results
func writeResults() {
	// Lock the mutex before reading from the map
	// can happen when we are still writing to the map
	mutex.Lock()
	defer mutex.Unlock()

	// Convert map keys (integers) to a slice and sort
	var keys []uint32
	for k := range respondingIPs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	// Write sorted results to the file
	filename := fmt.Sprintf("ping_results_%d.txt", time.Now().Unix())
	logFile, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating results file:", err)
		return
	}
	defer logFile.Close()

	for _, k := range keys {
		_, err := logFile.WriteString(respondingIPs[k] + "\n")
		if err != nil {
			fmt.Println("Error writing IP to results file:", err)
		}
	}
	// print total number of responding IPs
	// print in human readable format, ie if 1000, print 1,000
	fmt.Printf("Total number of responding IPs: %s\n", humanizeNumber(int64(len(keys))))
	fmt.Println("Results written to", filename)
}

// Main function
func main() {

	data, err := fetchIPData(awsIpRangesUrl)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Setting up signal handling
	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		fmt.Println("\nInterrupt received, writing results...")
		writeResults()
		os.Exit(0)
	}()

	go listenPingForReplies() // Start listening for ICMP Echo Replies

	for _, prefix := range data.Prefixes {
		if prefix.Service == "AMAZON" || prefix.Service == "EC2" || prefix.Service == "GLOBALACCELERATOR" {
			fmt.Printf("%s - %s - %s - %s\n", prefix.IPPrefix, prefix.Region, prefix.NetworkBorderGroup, prefix.Service)
			expandedIps, err := expandCIDR(prefix.IPPrefix)
			if err != nil {
				fmt.Println("Error expanding CIDR:", err)
				continue
			}
			rate := time.Second / time.Duration(ratelimit)
			throttle := time.Tick(rate)

			// Shuffle IPs to randomize the order
			rand.Seed(time.Now().UnixNano())
			rand.Shuffle(len(expandedIps), func(i, j int) { expandedIps[i], expandedIps[j] = expandedIps[j], expandedIps[i] })
			for _, ip := range expandedIps {

				<-throttle // Wait for the next tick
				go sendICMPEchoRequest(ip)
			}
		}
	}

	// Sleep for 5 seconds to allow for any delayed replies
	time.Sleep(5 * time.Second)

	// Normal completion:  write results
	writeResults()
}
