// This executable serves only disposable supervisor fixtures.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "fixture-child" {
		os.Exit(2)
	}
	mode := os.Args[2]
	if mode == "ignore-term" || mode == "flood" {
		signal.Ignore(syscall.SIGTERM)
	}
	data, _ := json.Marshal(map[string]any{"role": os.Getenv("AGENTMUX_KERNEL_ROLE"), "pid": os.Getpid(), "args": os.Args[3:], "instance": os.Getenv("AGENTMUX_INSTANCE_ID"), "loader": os.Getenv("LD_PRELOAD"), "private": os.Getenv("UNRELATED_SECRET")})
	fmt.Println(string(data))
	if mode == "exit" {
		return
	}
	if mode == "flood" {
		fmt.Print(strings.Repeat("x", 64*1024))
	}
	for {
		time.Sleep(time.Second)
	}
}
