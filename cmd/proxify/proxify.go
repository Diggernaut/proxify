package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/internal/runner"
)

func main() {

	options := runner.ParseOptions()

	proxifyRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	// Setup close handler
	go func() {
		c := make(chan os.Signal, 1) //added size 1 to channel buffer
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			fmt.Println("\r- Ctrl+C pressed in Terminal")
			proxifyRunner.Close()
			os.Exit(0)
		}()
	}()

	err = proxifyRunner.Run()
	if err != nil {
		gologger.Fatal().Msgf("Could not run proxify: %s\n", err)
	}

}
