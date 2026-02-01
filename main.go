// main.go
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	// Ambil konfigurasi dari Environment Variable (yang diset Docker nanti)
	dbHost := os.Getenv("DB_HOST")
	port := os.Getenv("APP_PORT")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Halo! Finance API Jalan.\nKoneksi ke Database host: %s", dbHost)
	})

	fmt.Printf("Server jalan di port %s...\n", port)
	http.ListenAndServe(":"+port, nil)
}