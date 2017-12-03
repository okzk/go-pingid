package main

import (
	"bufio"
	"fmt"
	"github.com/okzk/go-pingid"
	"os"
	"strings"
)

func fatalIfError(err error) {
	if err != nil {
		panic(err)
	}
}

func getOnetimePassword() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter OTP: ")
	otp, err := reader.ReadString('\n')
	fatalIfError(err)
	return strings.TrimSpace(otp)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("USAGE: %s USER_NAME\n", os.Args[0])
		os.Exit(1)
	}
	userName := os.Args[1]

	p, err := pingid.NewPingIDFromFile("./pingid.properties")
	fatalIfError(err)

	// Online Authentication Flow.
	res, err := p.AuthenticateOnline(userName, "")
	fatalIfError(err)
	if res.Success() {
		fmt.Println("Authentication Result: SUCCESS")
		os.Exit(0)
	}
	fmt.Println(res.ErrorMsg)
	if res.SessionID == "" {
		fmt.Println("Authentication Result: FAIL")
		os.Exit(1)
	}

	// Offline Authentication Flow.
	otp := getOnetimePassword()
	res, err = p.AuthenticateOffline(res.UniqueMsgID, userName, otp, "")
	fatalIfError(err)
	if res.Success() {
		fmt.Println("Authentication Result: SUCCESS")
		os.Exit(0)
	}

	fmt.Println(res.ErrorMsg)
	fmt.Println("Authentication Result: FAIL")
	os.Exit(1)
}
