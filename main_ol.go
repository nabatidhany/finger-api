package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

// Inisialisasi Redis dan Context
var ctxs = context.Background()
var rdbs = redis.NewClient(&redis.Options{
	Addr: "localhost:6379",
})

// Konversi array string ke FLOAT32 byte array
func convertToFloat32ByteArray(vector []string) ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, v := range vector {
		val, err := strconv.ParseFloat(v, 32)
		if err != nil {
			return nil, err
		}
		binary.Write(buf, binary.LittleEndian, float32(val))
	}
	return buf.Bytes(), nil
}

// Fungsi untuk membuat indeks RedisSearch
func createIndex() error {
	_, err := rdb.Do(ctx, "FT.DROPINDEX", "fingerprint_idx").Result()
	if err != nil && err != redis.Nil {
		fmt.Println("Gagal menghapus indeks lama:", err)
	}

	_, err = rdb.Do(ctx, "FT.CREATE", "fingerprint_idx",
		"ON", "HASH",
		"PREFIX", "1", "fingerprint:",
		"SCHEMA",
		"vector", "VECTOR", "HNSW", "6",
		"DIM", "3", "TYPE", "FLOAT32", "DISTANCE_METRIC", "COSINE").Result()

	if err != nil {
		fmt.Println("Gagal membuat indeks:", err)
		return err
	}

	fmt.Println("Indeks berhasil dibuat")
	return nil
}

func mainol() {
	app := fiber.New()

	// Membuat indeks RedisSearch saat aplikasi dijalankan
	if err := createIndex(); err != nil {
		log.Fatal("Gagal membuat indeks RedisSearch:", err)
	}

	// API untuk menyimpan fingerprint ke Redis
	app.Post("/save-fingerprint", func(c *fiber.Ctx) error {
		var data struct {
			ID     string   `json:"id"`
			Vector []string `json:"vector"`
		}

		if err := c.BodyParser(&data); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		// Konversi vektor ke format FLOAT32 byte array
		vecBytes, err := convertToFloat32ByteArray(data.Vector)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Vector conversion failed"})
		}
		fmt.Println("Vector bytes:", vecBytes)
		// Simpan fingerprint di Redis
		key := fmt.Sprintf("fingerprint:%s", data.ID)
		err = rdb.HSet(ctx, key, "vector", vecBytes).Err()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to store fingerprint"})
		}

		return c.JSON(fiber.Map{"message": "Fingerprint saved"})
	})

	// API untuk mencari fingerprint terdekat
	app.Post("/match-fingerprint", func(c *fiber.Ctx) error {
		var data struct {
			Vector []string `json:"vector"`
		}

		if err := c.BodyParser(&data); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		// Konversi vektor ke FLOAT32 byte array
		queryVector, err := convertToFloat32ByteArray(data.Vector)
		fmt.Println("Query vector:", queryVector)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Vector conversion failed"})
		}

		// Jalankan pencarian vektor KNN
		query := []interface{}{
			"FT.SEARCH", "fingerprint_idx",
			"*=>[KNN 1 @vector $vector AS distance]", // Perbaiki format query KNN
			"SORTBY", "distance", "ASC",              // Urutkan berdasarkan jarak terkecil
			"PARAMS", "2", "vector", queryVector,
			"LIMIT", "0", "1",
		}

		res, err := rdb.Do(ctx, query...).Result()
		if err != nil {
			fmt.Println("Error saat mencari fingerprint:", err)
			return c.Status(500).JSON(fiber.Map{"error": "Error matching fingerprint"})
		}

		// Parsing hasil pencarian
		results, ok := res.([]interface{})
		if !ok || len(results) < 2 {
			return c.JSON(fiber.Map{"message": "No matching fingerprint found"})
		}

		matchedFingerprint := fmt.Sprintf("%v", results[1])

		return c.JSON(fiber.Map{"matched_fingerprint": matchedFingerprint})
	})

	log.Fatal(app.Listen(":3000"))
}
