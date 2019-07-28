package datastores

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
)

func SqliteConnection(filename string) *sql.DB {
	envRuntime := os.Getenv("ENV")
	log.Println(envRuntime)
	if envRuntime == "test" {
		fmt.Println("ENV is Test")
		_ = os.Remove(filename)
	}
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		log.Fatal(err)
	}
	return db
}
