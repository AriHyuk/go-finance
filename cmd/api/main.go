package main

import (
	"go-finance/pkg/database" // Ganti nama module sesuai go.mod kamu!
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func main() {
	// --- 1. SETUP CONFIG (VIPER) ---
	viper.SetConfigFile(".env")
	viper.AutomaticEnv() // Baca juga dari environment variable (bagus buat Docker)

	if err := viper.ReadInConfig(); err != nil {
		// Kalau di production kadang kita inject langsung env var tanpa file .env
		// Jadi warning aja, jangan fatal
		log.Println("Warning: Tidak bisa membaca file .env:", err)
	}

	// --- 2. SETUP DATABASE ---
	// Rakit DSN (Data Source Name)
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		viper.GetString("DB_USER"),
		viper.GetString("DB_PASSWORD"),
		viper.GetString("DB_HOST"),
		viper.GetString("DB_PORT"),
		viper.GetString("DB_NAME"),
	)

	// Panggil fungsi sakti yang kita buat di pkg/database
	dbPool, err := database.NewPostgresConnection(dsn)
	if err != nil {
		log.Fatalf("❌ Fatal: Gagal konek database: %v", err) // Aplikasi matiin aja kalau DB gak konek
	}
	// Jangan lupa tutup koneksi kalau main program berhenti
	defer dbPool.Close()

	// --- 3. SETUP ROUTER (GIN) ---
	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		// Kita coba cek status DB juga di endpoint ini
		err := dbPool.Ping(c.Request.Context())
		status := "Database OK"
		if err != nil {
			status = "Database Down: " + err.Error()
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "day 1 belajar go-lang : adili jokowi",
			"db_status": status,
			"app_env": viper.GetString("APP_ENV"),
		})
	})

	// --- 4. RUN SERVER ---
	port := viper.GetString("APP_PORT")
	log.Printf("🚀 Server berjalan di port %s", port)
	if err := r.Run(port); err != nil {
		log.Fatalf("Gagal menjalankan server: %v", err)
	}
}