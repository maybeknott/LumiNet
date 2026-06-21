package diagnostics

import "sync"

// RunScanPool spins up workers to perform concurrent scanning.
func RunScanPool(ips []string, workers int, scanFn func(string)) {
	if len(ips) == 0 || workers <= 0 {
		return
	}
	
	jobs := make(chan string, len(ips))
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				scanFn(ip)
			}
		}()
	}
	wg.Wait()
}
