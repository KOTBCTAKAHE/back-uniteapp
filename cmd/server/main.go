package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/KOTBCTAKAHE/back-uniteapp/internal/protocol"
	"github.com/KOTBCTAKAHE/back-uniteapp/internal/server"
)

func main() {
	tcpPort := flag.Int("tcp-port", protocol.DefaultTCPPort, "TCP port for control plane")
	udpPort := flag.Int("udp-port", protocol.DefaultUDPPort, "UDP port for data plane")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("=== UNITEAPP Server ===")
	log.Printf("Protocol version: %d", protocol.ProtocolVersion)

	srv, err := server.New(*tcpPort, *udpPort)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Handle shutdown signals.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		os.Exit(0)
	}()

	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
