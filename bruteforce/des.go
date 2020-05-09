package main

import (
	"encoding/binary"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"

	"github.com/andrewarchi/adobe-cred/des"
)

var (
	cipher uint64 = 0x2fca9b003de39778
	plain  uint64 = binary.BigEndian.Uint64([]byte("password"))

	start      uint64
	end        uint64
	step       uint64
	cpuProfile string
)

// DES brute force of all 56-bit keys.
func main() {
	flag.Uint64Var(&start, "start", 0, "starting search bound")
	flag.Uint64Var(&end, "end", 1<<56, "ending search bound")
	flag.Uint64Var(&step, "step", 1<<24, "search increment")
	flag.StringVar(&cpuProfile, "cpuprofile", "", "write cpu profile to file")
	flag.Parse()

	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()

		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			pprof.StopCPUProfile()
			os.Exit(1)
		}()
	}

	k := start
	done := false
	var mu sync.Mutex

	workers := runtime.GOMAXPROCS(-1)
	log.Printf("Searching with %d workers\n", workers)
	t0 := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			for {
				mu.Lock()
				if k == end || done {
					mu.Unlock()
					break
				}
				min, max := k, k+step
				k = max
				mu.Unlock()

				t := time.Now()
				key, ok, err := desSearchRange(min, max)
				if err != nil {
					panic(err)
				}

				if ok {
					log.Printf("Found key 0x%x (0x%x) in %v\n", key, des.Intersperse56(key), time.Since(t0))
					mu.Lock()
					done = true
					mu.Unlock()
					break
				}
				now := time.Now()
				log.Printf("Searched 0x%x to 0x%x in %v, %v elapsed\n", min, max, now.Sub(t), now.Sub(t0))
			}

			wg.Done()
		}()

		time.Sleep(1000) // space out workers
	}
	wg.Wait()
}

func desSearchRange(min, max uint64) (uint64, bool, error) {
	for i := min; i < max; i++ {
		key := des.Intersperse56(i)
		d := des.NewCipher(key)
		out := d.DecryptBlock(cipher)
		if out == plain {
			return i, true, nil
		}
	}
	return 0, false, nil
}
