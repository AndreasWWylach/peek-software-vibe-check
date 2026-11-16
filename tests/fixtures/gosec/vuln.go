package main

import (
	"database/sql"
	"os"
	"os/exec"
)

func main() {
	userInput := os.Args[1]
	cmd := exec.Command("sh", "-c", userInput)
	_ = cmd.Run()

	db, _ := sql.Open("sqlite3", "x.db")
	_ = db.QueryRow("SELECT * FROM users WHERE id = " + userInput)
}
