package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPostgresConnection(dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("gagal parsing config DB: %w", err)
	}

	config.MaxConns = 10
	config.MinConns = 2
	config.MaxConnLifetime = 1 * time.Hour
	config.MaxConnIdleTime = 30 * time.Minute

	// --- RETRY LOGIC (Code Tambahan) ---
	var dbPool *pgxpool.Pool
	var poolErr error
	counts := 0
    maxRetries := 5 // Kita coba maksimal 5 kali (total 10 detik)

	for {
		// Coba buat koneksi
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		
        // Kita init poolnya
		dbPool, poolErr = pgxpool.NewWithConfig(ctx, config)
        
        // Langsung kita Ping untuk memastikan DB beneran hidup
		if poolErr == nil {
			poolErr = dbPool.Ping(ctx)
		}
		
        cancel() // Selalu cancel context setelah dipakai biar gak memory leak

		if poolErr == nil {
			// SUKSES! Keluar dari loop
			log.Println("✅ Berhasil terkoneksi ke PostgreSQL")
			return dbPool, nil
		}

		// Kalau Gagal...
		counts++
		log.Printf("⚠️ Gagal konek ke DB (Percobaan %d/%d): %v", counts, maxRetries, poolErr)
		
		if counts >= maxRetries {
			// Kalau sudah 5x masih gagal, baru nyerah (return error)
			return nil, fmt.Errorf("sudah mencoba %d kali tapi tetap gagal: %w", maxRetries, poolErr)
		}

		// Tunggu 2 detik sebelum coba lagi
		log.Println("⏳ Menunggu 2 detik sebelum mencoba lagi...")
		time.Sleep(2 * time.Second)
	}
}