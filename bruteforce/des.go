package main

import (
	"crypto/des"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"time"
)

var cipher = [8]byte{0x2f, 0xca, 0x9b, 0x00, 0x3d, 0xe3, 0x97, 0x78}
var plain = [8]byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}

// DES brute force of all 56-bit keys.
func main() {
	start := time.Now()

	k := uint64(0)
	done := false
	var mu sync.Mutex

	workers := runtime.GOMAXPROCS(-1)
	fmt.Printf("Searching with %d workers\n", workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			for {
				mu.Lock()
				if k >= 1<<56 || done {
					mu.Unlock()
					break
				}
				min, max := k, k+1<<24
				k = max
				mu.Unlock()

				key, ok, err := desSearchRange(min, max)
				if err != nil {
					panic(err)
				}

				if ok {
					fmt.Printf("Found key %x in %v\n", key, time.Since(start))
					mu.Lock()
					done = true
					mu.Unlock()
					break
				}
				fmt.Printf("Searched %x to %x, %v elapsed\n", min, max, time.Since(start))
			}

			wg.Done()
		}()

		time.Sleep(500) // space out workers
	}
	wg.Wait()
}

func desSearchRange(min, max uint64) (uint64, bool, error) {
	var key [8]byte
	var out [8]byte
	for i := min; i < max; i++ {
		k := IntersperseKey(i)
		binary.BigEndian.PutUint64(key[:], k)
		d, err := des.NewCipher(key[:])
		if err != nil {
			return 0, false, err
		}
		d.Decrypt(out[:], cipher[:])
		if out == plain {
			return k, true, nil
		}
	}
	return 0, false, nil
}
