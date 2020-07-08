package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"

	"log"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func icmpping() {
	var targetIP string = "8.8.8.8"

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("listen err, %s", err)
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(targetIP)}); err != nil {
		log.Fatalf("WriteTo err, %s", err)
	}

	rb := make([]byte, 1500)
	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		log.Fatal(err)
	}
	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), rb[:n])
	if err != nil {
		log.Fatal(err)
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		log.Printf("got reflection from %v", peer)
	default:
		log.Printf("got %+v; want echo reply", rm)
	}
}

func localAddresses() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Print(fmt.Errorf("localAddresses: %v\n", err.Error()))
		return
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Print(fmt.Errorf("localAddresses: %v\n", err.Error()))
			continue
		}
		for _, a := range addrs {
			log.Printf("%v %v\n", i.Name, a)
		}
	}
}

func secondsToMinutes(inSeconds uint32) string {
	minutes := inSeconds / 60
	var s string
	if minutes > 1 {
		s = "s"
	}
	str := fmt.Sprintf("%d min%s", minutes, s)
	return str
}

// ipToArpa reverses IPv4 addr to ARPA format
// 1.2.3.4 becomes 4.3.2.1.in-addr.arpa
func ipToArpa(ip string) string {
	parts := strings.Split(ip, ".")
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa"
}

func addQuestion(dnsMsg *dns.Msg, z string, t uint16) *dns.Msg {
	dnsMsg.Id = dns.Id()
	dnsMsg.RecursionDesired = true
	dnsMsg.Question = append(dnsMsg.Question, dns.Question{z, t, dns.ClassINET})
	return dnsMsg
}

func printHeader(target string, r *dns.Msg) {
	fmt.Println("Name: ", target)
	fmt.Print("Address")
	if len(r.Answer) > 1 {
		fmt.Print("es")
	}
	fmt.Println(":")
}

// UNUSED to mark anything as unused.
func UNUSED(param interface{}) {}

func printAnswer(msg, r *dns.Msg, target string, err error, vPrintHeader *bool) {
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}

	if (r == nil) || ((r.Answer == nil) && (msg.Question[0].Qtype == dns.TypeA || msg.Question[0].Qtype == dns.TypeAAAA)) {
		fmt.Printf("*** UnKnown can't find %s: Non-existent domain\n", target)
		return
	}
	if r.Answer != nil {
		for _, ans := range r.Answer {
			switch ans.(type) {
			case *dns.A, *dns.AAAA:
				if !*vPrintHeader {
					printHeader(target, r)
					*vPrintHeader = true
				}
			}
			switch ans.(type) {
			case *dns.A:
				{
					Arecord := ans.(*dns.A)
					fmt.Printf("\t%s\n", Arecord.A)
				}
			case *dns.AAAA:
				{
					Arecord := ans.(*dns.AAAA)
					fmt.Printf("\t%s\n", Arecord.AAAA)
				}
			case *dns.TXT:
				{
					txt := ans.(*dns.TXT)
					fmt.Printf("%s  text = \n", target)
					fmt.Printf("\t\"%s\"\n\n", txt.Txt[0])
				}
			case *dns.DNSKEY:
				{
					dnskey := ans.(*dns.DNSKEY)
					fmt.Printf("Flags: %d\n", dnskey.Flags)
					fmt.Printf("Protocol: %d\n", dnskey.Protocol)
					fmt.Printf("Algorithm: %s\n", dns.AlgorithmToString[dnskey.Algorithm])
					fmt.Printf("Public Key: %s\n", dnskey.PublicKey)
				}
			case *dns.CNAME:
				{
					cname := ans.(*dns.CNAME)
					fmt.Printf("%s\tcanonical name = %s\n", target, cname.Target)
				}
			case *dns.PTR:
				{
					ptr := ans.(*dns.PTR)
					fmt.Printf("%s\tname = %s\n", target, ptr.Ptr)
				}

			case *dns.MX:
				{
					mx := ans.(*dns.MX)
					fmt.Printf("%s\tMX preference = %d, mail exchanger = %s\n", target, mx.Preference, mx.Mx)
				}

			case *dns.NS:
				{
					ns := ans.(*dns.NS)
					fmt.Printf("%s\t nameserver = %s\n", target, ns.Ns)

				}

			case *dns.SOA:
				{
					soa := ans.(*dns.SOA)
					fmt.Printf("\tprimary name server = %s\n", soa.Ns)
					fmt.Printf("\tresponsible mail addr = %s\n", soa.Mbox)
					fmt.Printf("\tserial  = %d\n", soa.Serial)
					fmt.Printf("\trefresh = %d (%s)\n", soa.Refresh, secondsToMinutes(soa.Refresh))
					fmt.Printf("\tretry   = %d (%s)\n", soa.Retry, secondsToMinutes(soa.Retry))
					fmt.Printf("\texpire  = %d (%s)\n", soa.Expire, secondsToMinutes(soa.Expire))
					fmt.Printf("\tdefault TTL = %d (%s)\n", soa.Minttl, secondsToMinutes(soa.Minttl))
				}

			}
		}
	}
	if r.Ns != nil {
		fmt.Println(target)
		for _, ans := range r.Ns {
			switch ans.(type) {
			case *dns.SOA:
				{
					soa := ans.(*dns.SOA)
					fmt.Printf("\tprimary name server = %s\n", soa.Ns)
					fmt.Printf("\tresponsible mail addr = %s\n", soa.Mbox)
					fmt.Printf("\tserial  = %d\n", soa.Serial)
					fmt.Printf("\trefresh = %d (%s)\n", soa.Refresh, secondsToMinutes(soa.Refresh))
					fmt.Printf("\tretry   = %d (%s)\n", soa.Retry, secondsToMinutes(soa.Retry))
					fmt.Printf("\texpire  = %d (%s)\n", soa.Expire, secondsToMinutes(soa.Expire))
					fmt.Printf("\tdefault TTL = %d (%s)\n", soa.Minttl, secondsToMinutes(soa.Minttl))
				}
			}
		}
	}
}

var (
	dnsClient         dns.Client
	recursionDesired  bool   = false
	defaultNameServer string = "8.8.8.8"
	defaultPort       string = "53"
	defaultMsg        dns.Msg
	defaultLookupType string = "A+AAAA"
)

func internalnslookup(nslookupType, target, server string) {

	var port string
	parts := strings.Split(server, ":")
	if len(parts) > 1 {
		server = parts[0]
		port = parts[1]
	} else {
		port = defaultPort
	}
	c := dnsClient

	// doesn't work yet, tcp-tls (DoH / DoT)
	if c.Net == "tcp" {
		port = "443"
	}

	nameserver := net.JoinHostPort(server, port)

	names, err := net.LookupAddr(server)
	if err != nil {
		return
	}
	fmt.Println("Server:  ", names[0])
	fmt.Println("Address: ", server)
	fmt.Println()

	msg := defaultMsg

	// DNSSec
	// msg.SetEdns0(4096, true)

	m := map[string]uint16{
		"A":      dns.TypeA,
		"ANY":    dns.TypeANY,
		"AAAA":   dns.TypeAAAA,
		"CNAME":  dns.TypeCNAME,
		"DNSKEY": dns.TypeDNSKEY,
		"MX":     dns.TypeMX,
		"NS":     dns.TypeNS,
		"PTR":    dns.TypePTR,
		"SOA":    dns.TypeSOA,
		"SRV":    dns.TypeSRV,
		"TXT":    dns.TypeTXT,
	}

	nslookupTypeParts := strings.Split(nslookupType, "+")
	bPrintHeader := false
	var (
		prevr *dns.Msg = nil
		mainR *dns.Msg = &dns.Msg{}
	)
	UNUSED(prevr)
	for _, nslookupType := range nslookupTypeParts {
		lookupType := strings.ToUpper(nslookupType)
		dnslookupType, ok := m[lookupType]
		if !ok { // if nothing found, default to A lookup
			dnslookupType = dns.TypeA
		}

		switch dnslookupType {
		case dns.TypePTR:

			target = ipToArpa(target)
			fallthrough
			// x msg.RecursionDesired = true
			// x msg.SetQuestion(dns.Fqdn(arpa), dnslookupType)
			// x r, t, err := c.Exchange(&msg, nameserver)
			// x UNUSED(t)   // instead of _ at the point of declaration
			// x UNUSED(err) // ditto
			// x printAnswer(r, arpa)

		case dns.TypeANY, dns.TypeMX, dns.TypeNS, dns.TypeSOA, dns.TypeTXT, dns.TypeDNSKEY,
			dns.TypeSRV:
			{
				msg.SetQuestion(dns.Fqdn(target), dnslookupType)
				msg.RecursionDesired = recursionDesired

				// r, t, err := c.Exchange(&msg, nameserver)
				// // if there's a response, and there's a truncated flag
				// if r.MsgHdr.Truncated {
				// 	c.Net = "tcp" // re-run the query over tcp
				// 	r, t, err = c.Exchange(&msg, nameserver)
				// }
				// UNUSED(t)   // instead of _ at the point of declaration
				// UNUSED(err) // ditto
				// printAnswer(r, target, err)

			}
		case dns.TypeCNAME:
			{
				msg.SetQuestion(dns.Fqdn(target), dnslookupType)

				// r, t, err := c.Exchange(&msg, nameserver)
				// UNUSED(t)   // instead of _ at the point of declaration
				// UNUSED(err) // ditto
				// printAnswer(r, target, err)

			}
		default:
		case dns.TypeA, dns.TypeAAAA:
			{
				msg.SetQuestion(dns.Fqdn(target), dnslookupType)

				// r, t, err := c.Exchange(&msg, nameserver)
				// UNUSED(t)
				// if err != nil {
				// 	fmt.Printf("Error: %v", err)
				// 	return
				// }

				// if len(r.Answer) == 0 {
				// 	fmt.Printf("*** UnKnown can't find %s: Non-existent domain\n", target)
				// } else {
				// 	fmt.Println("Name: ", target)
				// 	fmt.Print("Address")
				// 	if len(r.Answer) > 1 {
				// 		fmt.Print("es")
				// 	}
				// 	fmt.Println(":")
				// 	for _, ans := range r.Answer {
				// 		switch ans.(type) {
				// 		case *dns.A:
				// 			{
				// 				Arecord := ans.(*dns.A)
				// 				fmt.Printf("\t%s\n", Arecord.A)
				// 			}
				// 		case *dns.AAAA:
				// 			{
				// 				Arecord := ans.(*dns.AAAA)
				// 				fmt.Printf("\t%s\n", Arecord.AAAA)
				// 			}
				// 		}
				// 	}
				// }
			}
		}

		// do query here - temporarily moved outside the loop
		r, t, err := c.Exchange(&msg, nameserver)
		UNUSED(err)
		UNUSED(t) // instead of _ at the point of declaration
		// // if there's a response, and there's a truncated flag
		if r.MsgHdr.Truncated {
			c.Net = "tcp" // re-run the query over tcp
			r, t, err = c.Exchange(&msg, nameserver)
			c.Net = "udp" // switch back to udp, or DoT in the future
		}
		// // If previous query is AAAA or A and current query is AAAA or A
		// // and previous answer and current answer is nil, skip printing the answer
		// if (prevr != nil) &&
		// 	(((prevr.Question[0].Qtype == dns.TypeA) || (prevr.Question[0].Qtype == dns.TypeAAAA)) &&
		// 		((r.Question[0].Qtype == dns.TypeA) || (r.Question[0].Qtype == dns.TypeAAAA))) &&
		// 	(prevr.Answer == nil && r.Answer == nil) {
		// 	continue
		// }
		// printAnswer(&msg, r, target, err, &bPrintHeader)
		// prevr = r
		mainR.Answer = append(mainR.Answer, r.Answer...)
		mainR.Ns = append(mainR.Ns, r.Ns...)
	}
	printAnswer(&msg, mainR, target, err, &bPrintHeader)
}

func nslookup() {
	nsLookupType := flag.String("type", defaultLookupType, "The type of DNS to resolve")
	flag.Parse()
	parameters := flag.Args()

	if len(parameters) == 0 {
		fmt.Println("No parameters supplied.")
		return
	}

	target := parameters[0]
	server := defaultNameServer
	var port string
	if len(parameters) > 1 {
		server = parameters[1]
	}
	parts := strings.Split(server, ":")
	if len(parts) > 1 {
		port = parts[1]
	} else {
		port = "53"
	}
	nameserver := net.JoinHostPort(server, port)
	internalnslookup(*nsLookupType, target, nameserver)
}

func interactiveNSlookup() {
	var nslookupType, domainNameOrCmd, server string
	server = defaultNameServer
	nslookupType = defaultLookupType
	// enable this
	myStdin, err := os.Open("c:\\temp\\test.txt") // if testing from VS Code
	if err == nil {
		defer myStdin.Close()
	} else {
		// OR enable this
		myStdin = os.Stdin
	}
	origserver := server
	reader := bufio.NewScanner(myStdin)
	for {
		server = origserver
		fmt.Print("> ")
		reader.Scan()
		// set type=ns
		// www.google.com

		text := strings.TrimSuffix(reader.Text(), " ") // remove trailing spaces
		parts := strings.Split(text, " ")              // split into array, separator " "

		// the following sections are written in an odd manner, so as to reproduce
		// the behaviour of Windows nslookup

		if len(parts) == 1 {
			cmd := strings.ToLower(parts[0])
			if cmd == "exit" {
				return
			} else if (cmd == "?") || (cmd == "help") {
				// dump help...
				fmt.Println("NAME\t\t- print info about the host/domain NAME using default server")
				fmt.Println("NAME1 NAME2\t- as above, but use NAME2 as server")
				fmt.Println("help or ?\t- print info on common commands")
				fmt.Println("set OPTION\t- set an option")
				fmt.Println("    [no]recurse\t- ask for recursive answer to query")
				fmt.Println("    type=X\t- set query type (ex. A,AAAA,A+AAAA,ANY,CNAME,MX,NS,PTR,SOA,SRV)")
				fmt.Println("exit\t\t- exit the program")
				fmt.Println()
			} else {
				domainNameOrCmd = parts[0]
				goto dolookup
			}
		} else if len(parts) > 0 {
			cmd := strings.ToLower(parts[0])
			if cmd == "set" {
				var params string
				if len(parts) > 1 {
					params = strings.ToLower(parts[1])
				}
				paramparts := strings.Split(params, "=") // set type=A

				switch len(paramparts) {
				case 1:
					{
						switch params {
						case "all": // set all
							{
								fmt.Printf(" port=%s\n", defaultPort)
								fmt.Printf(" type=%s\n", nslookupType)
								fmt.Printf(" server=%s\n", origserver)
								fmt.Println()
							}
						case "recurse": // set recurse
							{
								recursionDesired = true
							}
						case "norecurse": // set norecurse
							{
								recursionDesired = false
							}
						}

					}
				case 2: // set type=x or set querytype=x
					{
						switch paramparts[0] {
						case "type", "querytype":
							nslookupType = paramparts[1]
						}
					}
				}

				// if len(paramparts) >= 1 {
				// 	paramparts = strings.Split(params, " ")
				// 	if (len(paramparts) >= 1) && (cmd == "set") {
				// 		switch params {
				// 		case "all":
				// 			{
				// 				fmt.Printf(" port=%s\n", defaultPort)
				// 				fmt.Printf(" type=%s\n", nslookupType)
				// 				fmt.Printf(" server=%s\n", origserver)
				// 			}
				// 		case "recurse":
				// 			{
				// 				recursionDesired = true
				// 			}
				// 		case "norecurse":
				// 			{
				// 				recursionDesired = false
				// 			}
				// 		}
				// 	}
				// } else if len(paramparts) == 2 {
				// 	switch paramparts[0] {
				// 	case "type", "querytype":
				// 		nslookupType = paramparts[1]
				// 	}
				// }
			} else if cmd == "?" || cmd == "help" {
				// already parsed
			} else if cmd == "server" {
				origserver = parts[1]
			} else { // NAME1 NAME2
				domainNameOrCmd = cmd // NAME1
				if len(parts) > 1 {   // temporarily change the query server
					server = parts[1] // NAME2
				}
			}
		}
	dolookup:
		if domainNameOrCmd != "" {
			internalnslookup(nslookupType, domainNameOrCmd, server)
			fmt.Println()
			domainNameOrCmd = ""
		}
	}
}

// working prototype, tested in VS Code, 29 Jun 2020
func main() {

	icmpping()
	localAddresses()

	interactive := len(os.Args) <= 1
	if interactive {
		interactiveNSlookup()
	} else {
		nslookup()
	}
}
