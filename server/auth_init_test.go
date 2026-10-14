package server

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthInitCannotReplaceExistingPassword(t *testing.T) {
	// This HTTP regression necessarily writes the global bootstrap setting.
	// Opt in only in the unpublished, disposable Compose test database.
	if os.Getenv("ARTEX_TEST_DISPOSABLE_DB") != "1" {
		t.Skip("requires explicit disposable database opt-in")
	}
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	// Check the actual database before db.Open can apply migrations or seeds.
	probe, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	var database string
	err = probe.QueryRow(`SELECT current_database()`).Scan(&database)
	_ = probe.Close()
	if err != nil {
		t.Fatal(err)
	}
	if database != "artex_test" {
		t.Fatal("bootstrap regression requires the artex_test disposable database")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	before, existed, err := pg.GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	if before != "" {
		t.Skip("admin password already initialized in this database")
	}
	defer func() {
		if existed {
			_ = pg.SetSetting(authPassKey, before)
		} else {
			_, _ = pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
		}
	}()

	s := &Server{m: &Manager{pg: pg}, jwtKey: []byte(strings.Repeat("k", 32))}
	start := make(chan struct{})
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for _, password := range []string{"first-init-password", "second-init-password"} {
		wg.Add(1)
		go func(password string) {
			defer wg.Done()
			<-start
			r := httptest.NewRequest(http.MethodPost, "/api/auth/init", strings.NewReader(`{"password":"`+password+`"}`))
			w := httptest.NewRecorder()
			s.authInit(w, r)
			codes <- w.Code
		}(password)
	}
	close(start)
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusForbidden] != 1 {
		t.Fatalf("simultaneous initializers: %v", counts)
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil || hash == "" {
		t.Fatalf("admin password not stored: %v", err)
	}
	match := 0
	for _, password := range []string{"first-init-password", "second-init-password"} {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
			match++
		}
	}
	if match != 1 {
		t.Fatalf("stored password does not belong to exactly one initializer: %d", match)
	}
}
