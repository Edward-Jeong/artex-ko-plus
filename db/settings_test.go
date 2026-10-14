package db

import (
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestSettingsInitSettingConcurrent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	key := "test.auth.init." + uuid.NewString()
	defer d.Exec(`DELETE FROM settings WHERE key=$1`, key)

	const callers = 8
	start := make(chan struct{})
	results := make(chan string, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ok, err := d.InitSetting(key, fmt.Sprintf("password-hash-%d", i))
			if err != nil {
				results <- "error: " + err.Error()
			} else if ok {
				results <- fmt.Sprintf("password-hash-%d", i)
			} else {
				results <- "rejected"
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	winner, accepted := "", 0
	for result := range results {
		if result == "rejected" {
			continue
		}
		if len(result) >= 7 && result[:7] == "error: " {
			t.Fatal(result)
		}
		winner, accepted = result, accepted+1
	}
	if accepted != 1 {
		t.Fatalf("expected one initializer, got %d", accepted)
	}
	stored, ok, err := d.GetSetting(key)
	if err != nil || !ok || stored != winner {
		t.Fatalf("winning password hash replaced: stored=%q, winner=%q, err=%v", stored, winner, err)
	}
	if err := d.SetSetting(key, ""); err != nil {
		t.Fatal(err)
	}
	if initialized, err := d.InitSetting(key, "recovered-hash"); err != nil || !initialized {
		t.Fatalf("empty legacy setting cannot be initialized: %v, %v", initialized, err)
	}
}
