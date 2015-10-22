package main

import (
	"flag"
	"github.com/pangolinfq/pangolin/rendezvous/ecdns"
	"log"
	"time"
)

func main() {
	var pubKeyFile string
	flag.StringVar(&pubKeyFile, "public-key-file", "./pub.pem", "PEM eoncoded ECDSA public key file")
	flag.Parse()

	pubKey, err := ecdns.LoadPublicKey(pubKeyFile)
	if err != nil {
		log.Fatalf("FATAL: fail to load ECDSA public key: %s", err)
	}

	client := &ecdns.Client{[]string{"127.0.0.1:53"}, pubKey}
	log.Println(client.Query("pangolinfq.org", 10*time.Second))
}
