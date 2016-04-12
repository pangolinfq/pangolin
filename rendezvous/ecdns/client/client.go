package main

import (
	"flag"
	"log"
	"time"
	
	"github.com/pangolinfq/pangolin/rendezvous/ecdns"
)

func main() {
	var pubKeyFile string
	flag.StringVar(&pubKeyFile, "public-key-file", "./pub.pem", "PEM eoncoded ECDSA public key file")
	flag.Parse()

	pubKey, err := ecdns.LoadPublicKeyFile(pubKeyFile)
	if err != nil {
		log.Fatalf("FATAL: fail to load ECDSA public key: %s", err)
	}

	client := &ecdns.Client{Resolvers: []string{"8.8.8.8:53"}, PubKey: pubKey}
	log.Println(client.Query("pangolinfq.org", 20*time.Second))
}
