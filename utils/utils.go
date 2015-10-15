package utils

import (
	"log"
	"os"
	"strconv"
)

func RotateLog(filename string, pre *os.File) *os.File {
	if filename == "" {
		return pre
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("error opening log file: %s", err)
		return pre
	} else {
		// log has an internal mutex to guarantee mutual exclusion with log.Write
		log.SetOutput(f)
		if pre != nil {
			pre.Close()
		}
		return f
	}
}

func SavePid(filename string) {
	if filename == "" {
		return
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600)
	defer f.Close()
	if err != nil {
		log.Printf("error opening pid file: %s", err)
		return
	}
	f.Write([]byte(strconv.Itoa(os.Getpid())))
}
