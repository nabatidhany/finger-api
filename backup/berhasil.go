package backup

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

var (
	ctx = context.Background()
	rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
)

// ConvertToVector hashes the fingerprint template to a fixed-length float32 vector
func ConvertToVector(fingerprint []byte) []float32 {
	hash := md5.Sum(fingerprint)
	vector := make([]float32, 16)
	for i := 0; i < 16; i++ {
		vector[i] = float32(hash[i])
	}
	return vector
}

// VectorToBinary converts a float32 vector to a byte array (binary format)
func VectorToBinary(vector []float32) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, vector)
	if err != nil {
		log.Fatalf("Error converting vector to binary: %v", err)
	}
	return buf.Bytes()
}

// EnrollFingerprint handles saving fingerprint data to Redis
func EnrollFingerprint(c *fiber.Ctx) error {
	fingerprintData := c.Body()
	if len(fingerprintData) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No fingerprint data provided"})
	}

	vector := ConvertToVector(fingerprintData)
	vectorBinary := VectorToBinary(vector)
	fingerprintID := fmt.Sprintf("fingerprint:%x", md5.Sum(fingerprintData))

	err := rdb.HSet(ctx, fingerprintID, "vector", vectorBinary).Err()
	if err != nil {
		log.Println("Error saving fingerprint:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save fingerprint"})
	}
	fmt.Printf("Fingerprint enrolled: %s\n", fingerprintID)
	return c.JSON(fiber.Map{"message": "Fingerprint enrolled", "id": fingerprintID})
}

// SearchFingerprint performs KNN search in Redis
func SearchFingerprint(c *fiber.Ctx) error {
	fingerprintData := c.Body()
	if len(fingerprintData) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No fingerprint data provided"})
	}

	// Konversi fingerprint ke vektor
	scannedVector := ConvertToVector(fingerprintData)
	queryVector := VectorToBinary(scannedVector)

	// Query Redis dengan KNN Search
	rawResult, err := rdb.Do(ctx, "FT.SEARCH", "fingerprint_index",
		"*=>[KNN 1 @vector $query_vector AS score]",
		"PARAMS", "2", "query_vector", queryVector,
		"SORTBY", "score", "ASC",
		"DIALECT", "2").Result()

	if err != nil {
		log.Println("Error searching fingerprint:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to search fingerprint"})
	}

	// Debugging: Cetak hasil query untuk memastikan formatnya benar
	// log.Printf("Raw search result: %#v\n", rawResult)

	// Parsing hasil pencarian
	resultMap, ok := rawResult.(map[interface{}]interface{})
	if !ok {
		log.Println("Error: Unexpected search result format")
		return c.Status(500).JSON(fiber.Map{"error": "Invalid search result format"})
	}

	// Ambil daftar hasil pencarian
	results, ok := resultMap["results"].([]interface{})
	if !ok || len(results) == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "No fingerprint found"})
	}

	// Ambil fingerprint dengan skor terbaik
	bestMatch, ok := results[0].(map[interface{}]interface{})
	if !ok {
		return c.Status(500).JSON(fiber.Map{"error": "Invalid result structure"})
	}

	fingerprintID, _ := bestMatch["id"].(string)

	extraAttrs, ok := bestMatch["extra_attributes"].(map[interface{}]interface{})
	if !ok {
		return c.Status(500).JSON(fiber.Map{"error": "Invalid attributes format"})
	}

	scoreStr, _ := extraAttrs["score"].(string)
	score, err := strconv.ParseFloat(scoreStr, 64)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Invalid score format"})
	}
	fmt.Printf("Fingerprint found: %s (score: %.2f)\n", fingerprintID, score)
	return c.JSON(fiber.Map{
		"message":        "Fingerprint found",
		"fingerprint_id": fingerprintID,
		"score":          score,
	})
}

func createIndexIfNotExists() {
	_, err := rdb.Do(ctx, "FT.INFO", "fingerprint_index").Result()
	if err == nil {
		log.Println("Index fingerprint_index already exists.")
		return
	}

	// Buat index jika belum ada
	err = rdb.Do(ctx, "FT.CREATE", "fingerprint_index",
		"ON", "HASH",
		"PREFIX", "1", "fingerprint:",
		"SCHEMA", "vector", "VECTOR", "HNSW", "6",
		"TYPE", "FLOAT32", "DIM", "16", "DISTANCE_METRIC", "COSINE").Err()

	if err != nil {
		log.Fatalf("Failed to create index: %v", err)
	}
}

func backup() {
	app := fiber.New()
	createIndexIfNotExists()

	app.Post("/enroll", EnrollFingerprint)
	app.Post("/search", SearchFingerprint)

	log.Println("Server running on :3000")
	log.Fatal(app.Listen(":3000"))
}
