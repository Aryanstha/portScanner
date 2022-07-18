package main

import (
	"fmt"
	"os"
	"time"

	portscanner "github.com/anvie/port-scanner"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

type openPorts struct {
	IP   string
	PORT []int
}

func main() {
	open := []openPorts{}
	for _, ip := range publicIPS() {
		open = append(open, portScanner(ip))
	}
	fmt.Printf("%+v\n", open)
}

func publicIPS() []string {
	listPublicAddress := []string{}
	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION"))},
	)
	svc := ec2.New(sess)
	result, _ := svc.DescribeAddresses(&ec2.DescribeAddressesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("domain"),
				Values: aws.StringSlice([]string{"vpc"}),
			},
		},
	})
	if len(result.Addresses) == 0 {
		fmt.Printf("No elastic IPs for %s region\n", *svc.Config.Region)
	} else {
		for _, addr := range result.Addresses {
			listPublicAddress = append(listPublicAddress, aws.StringValue(addr.PublicIp))
		}
		return listPublicAddress
	}
	return listPublicAddress
}

// portScanner scan range 20-30000 through goroutines, opening a thread for each request
func portScanner(ip string) openPorts {

	// 22 -> SSH, 443 -> SSL, 80 -> HTTP, 1194 -> OPENVPN
	allowedPorts := []int{22, 443, 80, 1194}
	open := openPorts{}

	// 29980 threads := 1 thread = connection
	openedPorts := portscanner.NewPortScanner(ip, 2*time.Second, 29980).GetOpenedPort(20, 30000)

	for i := 0; i < len(openedPorts); i++ {
		port := openedPorts[i]
		if !(contains(allowedPorts, port)) {
			open.IP = ip
			open.PORT = append(open.PORT, port)
		}
	}
	return open
}

// contains compares the array with the object
func contains(slice []int, item int) bool {
	set := make(map[int]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}
	_, ok := set[item]
	return ok
}
