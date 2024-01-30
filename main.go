package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var (
	// rate limit is the number of ICMP Echo Requests we send per second
	ratelimit = 1000 // Rate limiter: pps per second
	// awsIPRangesURL is the URL to download the AWS IP ranges JSON
	awsIPRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

	// map to store responding IPs
	respondingIPs = make(map[uint32]string)

	// channel to signal to stop updating the map and return
	// Needed so we don't have to use mutex locks to prevent multiple goroutines from writing to the map at the same time
	stopUpdating = make(chan struct{})

	// icmpEchoRequestTemplate is the ICMP Echo Request packet template
	icmpEchoRequestTemplate []byte

	// rawSocketFd is the raw socket file descriptor
	rawSocketFd int
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return data, err
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return data, err
	}

	return data, nil
}

func buildPingPacket() {
	icmpEchoRequestTemplate = make([]byte, 8)
	icmpEchoRequestTemplate[0] = 8                             // Echo Request type
	icmpEchoRequestTemplate[1] = 0                             // Code 0
	binary.BigEndian.PutUint16(icmpEchoRequestTemplate[6:], 1) // Identifier

	// Calculate ICMP checksum
	var sum uint32
	for i := 0; i < len(icmpEchoRequestTemplate); i += 2 {
		sum += uint32(icmpEchoRequestTemplate[i])<<8 | uint32(icmpEchoRequestTemplate[i+1])
	}
	sum += (sum >> 16)
	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(icmpEchoRequestTemplate[2:], checksum)
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
		select {
		case <-stopUpdating:
			return
		default:
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
				respondingIPs[ipInt] = src.String()
			}
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

// Function to finalize the program and write results
func writeResults() {
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

// Function to initialize the raw socket
func initRawSocket() error {
	var err error
	rawSocketFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	return nil
}

// Function to send an ICMP Echo Request using raw sockets
// this is the fastest way to send ICMP Echo Requests, since we don't need to do a new dial for each ping request
// Instead we only use one file descriptor for the raw socket
func sendICMPEchoRequest(ip string) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		fmt.Printf("Invalid IP address: %s\n", ip)
		return
	}

	var addr [4]byte
	copy(addr[:], ipAddr.To4())

	dest := syscall.SockaddrInet4{
		Addr: addr,
	}

	if err := syscall.Sendto(rawSocketFd, icmpEchoRequestTemplate, 0, &dest); err != nil {
		fmt.Printf("Error sending to %s: %v\n", ip, err)
	}
}

// Takes a list of IPs and sends ICMP Echo Requests to them at a rate of ratelimit per second
func pingTargets(expandedIps []string) {

	// inteval is the number of milliseconds between each interval
	// in this case we check the sending rate every 10 milliseconds (100 times per second)
	interval := 10

	// ley's calculate the number of packets we need to send per interval
	targetPacketsPerInterval := ratelimit / (1000 / interval)

	// Setup ticker for packet sending
	ticker := time.NewTicker(time.Duration(interval) * time.Millisecond)
	defer ticker.Stop()

	ipIndex := 0
	for range ticker.C {
		select {
		case <-stopUpdating:
			// no more sending packets, user wants to exit
			return
		default:
			packetsThisInterval := 0

			for ipIndex < len(expandedIps) && packetsThisInterval < targetPacketsPerInterval {
				ipAddress := expandedIps[ipIndex]
				go sendICMPEchoRequest(ipAddress)
				packetsThisInterval++
				ipIndex++
			}
			if ipIndex >= len(expandedIps) {
				return
			}
		}
	}
}

// Main function
func main() {
	// Fetch the IP data
	data, err := fetchIPData(awsIPRangesURL)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Signal handling for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nInterrupt received, writing results...")
		close(stopUpdating) // Signal to stop updating the map
		// Just a little delay to make sure nothing is writing to the map
		time.Sleep(10 * time.Millisecond)
		writeResults()
		os.Exit(0) // Exit the program after writing results
	}()

	// Start listening for ICMP Echo Replies
	go listenPingForReplies()

	// Initialize the raw socket
	// Raw sockets are the fastest way to send ICMP Echo Requests in our case
	// as using a raw socket we don't need to dial for each request
	err = initRawSocket()
	if err != nil {
		fmt.Println("Error initializing raw socket:", err)
		fmt.Println("Make sure you run this program as root")
		return
	}

	// Build the ICMP packet template
	buildPingPacket()

	for _, prefix := range data.Prefixes {
		if prefix.Service == "AMAZON" || prefix.Service == "EC2" || prefix.Service == "GLOBALACCELERATOR" {
			expandedIps, err := expandCIDR(prefix.IPPrefix)
			if err != nil {
				fmt.Println("Error expanding CIDR:", err)
				continue
			}
			// now shuffle the IPs to randomize the order
			// This makes sure we don't hit all IPs in the same subnet at the same time
			rand.Shuffle(len(expandedIps), func(i, j int) { expandedIps[i], expandedIps[j] = expandedIps[j], expandedIps[i] })

			fmt.Println("Sending ICMP Echo Requests to", len(expandedIps), "IPs in", prefix.IPPrefix, prefix.Service, prefix.Region, prefix.NetworkBorderGroup)
			pingTargets(expandedIps)

		}
	}

	// Sleep to allow for any delayed replies before exiting
	time.Sleep(5 * time.Second)

	// Normal completion: write results
	writeResults()
}
