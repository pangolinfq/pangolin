package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/yinghuocho/golibfq/utils"
	
	"github.com/pangolinfq/pangolin/rendezvous/ecdns"
)

func loadData(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	data := make(map[string]string)
	for scanner.Scan() {
		s := strings.Split(strings.Trim(scanner.Text(), " \r\n"), " ")
		if len(s) != 2 {
			continue
		} else {
			data[s[0]] = s[1]
		}
	}
	return data, nil
}

func main() {
	var prvKeyFile string
	var dataFile string
	var address string
	var logFilename string
	var pidFilename string
	flag.StringVar(&prvKeyFile, "private-key-file", "./key.pem", "PEM eoncoded ECDSA private key file")
	flag.StringVar(&dataFile, "data-file", "./data.txt", "name-to-address data file")
	flag.StringVar(&address, "server-address", ":53", "address server listens on")
	flag.StringVar(&logFilename, "logfile", "", "file to record log")
	flag.StringVar(&pidFilename, "pidfile", "", "file to save process id")
	flag.Parse()

	// initiate log file
	logFile := utils.RotateLog(logFilename, nil)
	if logFilename != "" && logFile == nil {
		log.Printf("WARNING: fail to initiate log file")
	}

	prvKey, err := ecdns.LoadPrivateKey(prvKeyFile)
	if err != nil {
		log.Fatalf("FATAL: fail to load ECDSA private key: %s", err)
	}

	rawData, err := loadData(dataFile)
	if err != nil {
		log.Fatalf("FATAL: fail to load data: %s", err)
	}
	server := ecdns.NewServer(prvKey, rawData)
	server.Addr = address

	quit := make(chan bool)
	go func() {
		server.ListenAndServe()
		close(quit)
	}()

	// pid file
	utils.SavePid(pidFilename)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGTERM)

loop:
	for {
		select {
		case <-quit:
			log.Printf("quit signal received")
			break loop
		case s := <-c:
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				server.Close()
				break loop
			case syscall.SIGHUP:
				logFile = utils.RotateLog(logFilename, logFile)
			case syscall.SIGUSR1:
				// reload data
				rawData, err := loadData(dataFile)
				if err != nil {
					log.Printf("fail to load data: %s", err)
				}
				server.ReloadData(rawData)
				log.Printf("server data updated")
			}
		}
	}
	log.Printf("done")
}
