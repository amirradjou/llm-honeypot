// Command honeypot runs an SSH honeypot that hands attackers a fake,
// LLM-driven Linux shell and records everything they try.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "honeypot:", err)
		os.Exit(1)
	}
}

func run(_ []string) error {
	fmt.Println("llm-honeypot: nothing to do yet")
	return nil
}
