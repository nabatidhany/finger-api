package main

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
	// threshold = 50.0
)

// // ConvertToVector hashes the fingerprint template to a fixed-length float32 vector
// func ConvertToVector(fingerprint []byte) []float32 {
// 	hash := md5.Sum(fingerprint)
// 	vector := make([]float32, 16)
// 	for i := 0; i < 16; i++ {
// 		vector[i] = float32(hash[i])
// 	}
// 	return vector
// }

// // VectorToString converts a float32 vector to a hex string
// func VectorToString(vector []float32) string {
// 	var buf bytes.Buffer
// 	binary.Write(&buf, binary.LittleEndian, vector) // Menulis dalam format binary FLOAT32
// 	return buf.String()
// }

func ConvertToVector(fingerprint []byte) []float32 {
	if len(fingerprint) < 16 {
		panic("Fingerprint data too short")
	}

	vector := make([]float32, 16)
	for i := 0; i < 16; i++ {
		vector[i] = float32(fingerprint[i]) / 255.0 // Normalisasi ke [0,1]
	}
	return vector
}

func VectorToString(vector []float32) string {
	var buf bytes.Buffer
	for _, val := range vector {
		binary.Write(&buf, binary.LittleEndian, val)
	}
	return buf.String()
}

// EnrollFingerprint handles saving fingerprint data to Redis
func EnrollFingerprint(c *fiber.Ctx) error {
	fingerprintData := c.Body()
	fmt.Println("Fingerprint data:", fingerprintData)
	if len(fingerprintData) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No fingerprint data provided"})
	}

	vector := ConvertToVector(fingerprintData)

	// Periksa apakah panjang vektor sesuai dengan konfigurasi Redis (16 elemen)
	if len(vector) != 16 {
		log.Println("Error: Vector size mismatch! Expected 16, got", len(vector))
		return c.Status(400).JSON(fiber.Map{"error": "Invalid vector size"})
	}

	vectorString := VectorToString(vector)
	fingerprintID := fmt.Sprintf("fingerprint:%x", md5.Sum(fingerprintData))

	err := rdb.HSet(ctx, fingerprintID, "vector", vectorString).Err()
	if err != nil {
		log.Println("Error saving fingerprint:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save fingerprint"})
	}
	fmt.Printf("Fingerprint enrolled: %s\n", fingerprintID)
	return c.JSON(fiber.Map{"message": "Fingerprint enrolled", "id": fingerprintID})
}

const THRESHOLD = 0.0008 // Bisa disesuaikan berdasarkan uji coba

func SearchFingerprint(c *fiber.Ctx) error {
	fingerprintData := c.Body()
	if len(fingerprintData) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No fingerprint data provided"})
	}

	scannedVector := ConvertToVector(fingerprintData)
	queryVector := VectorToString(scannedVector)

	rawResult, err := rdb.Do(ctx, "FT.SEARCH", "fingerprint_index",
		"*=>[KNN 1 @vector $query_vector AS score]",
		"PARAMS", "2", "query_vector", queryVector,
		"SORTBY", "score", "ASC",
		"LIMIT", "0", "1",
		"DIALECT", "2").Result()

	// Debugging
	log.Printf("Raw search result: %#v\n", rawResult)

	if err != nil {
		log.Println("Error searching fingerprint:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to search fingerprint"})
	}

	// Pastikan hasil pencarian valid
	resultMap, ok := rawResult.(map[interface{}]interface{})
	if !ok {
		log.Println("Error: Unexpected search result format")
		return c.Status(500).JSON(fiber.Map{"error": "Invalid search result format"})
	}

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

	// Cek apakah skor di bawah threshold
	if score > THRESHOLD {
		return c.Status(404).JSON(fiber.Map{"error": "No fingerprint match found"})
	}

	// Jika di bawah threshold, berarti cocok
	return c.JSON(fiber.Map{
		"message":        "Fingerprint found",
		"fingerprint_id": fingerprintID,
		"score":          score,
	})
}

// func SearchFingerprint(c *fiber.Ctx) error {
// 	fingerprintData := c.Body()
// 	if len(fingerprintData) == 0 {
// 		return c.Status(400).JSON(fiber.Map{"error": "No fingerprint data provided"})
// 	}
// 	fmt.Println("Fingerprint data:", fingerprintData)
// 	fmt.Println("Panjang data fingerprint diterima:", len(fingerprintData))

// 	scannedVector := ConvertToVector(fingerprintData)
// 	queryVector := VectorToString(scannedVector)
// 	fmt.Println("Query vector:", queryVector)
// 	rawResult, err := rdb.Do(ctx, "FT.SEARCH", "fingerprint_index",
// 		"*=>[KNN 1 @vector $query_vector AS score]",
// 		"PARAMS", "2", "query_vector", queryVector,
// 		"SORTBY", "score", "ASC",
// 		"DIALECT", "2").Result()
// 	// "LIMIT", "0", "1").Result()

// 	// Debugging: log hasil pencarian
// 	log.Printf("Raw search result: %#v\n", rawResult)

// 	if err != nil {
// 		log.Println("Error searching fingerprint:", err)
// 		return c.Status(500).JSON(fiber.Map{"error": "Failed to search fingerprint"})
// 	}

// 	// Pastikan hasil pencarian valid
// 	resultMap, ok := rawResult.(map[interface{}]interface{})
// 	if !ok {
// 		log.Println("Error: Unexpected search result format")
// 		return c.Status(500).JSON(fiber.Map{"error": "Invalid search result format"})
// 	}

// 	results, ok := resultMap["results"].([]interface{})
// 	if !ok || len(results) == 0 {
// 		return c.Status(404).JSON(fiber.Map{"error": "No fingerprint found"})
// 	}

// 	// Ambil fingerprint dengan skor terbaik
// 	bestMatch, ok := results[0].(map[interface{}]interface{})
// 	if !ok {
// 		return c.Status(500).JSON(fiber.Map{"error": "Invalid result structure"})
// 	}

// 	fingerprintID, _ := bestMatch["id"].(string)

// 	extraAttrs, ok := bestMatch["extra_attributes"].(map[interface{}]interface{})
// 	if !ok {
// 		return c.Status(500).JSON(fiber.Map{"error": "Invalid attributes format"})
// 	}

// 	scoreStr, _ := extraAttrs["score"].(string)
// 	score, err := strconv.ParseFloat(scoreStr, 64)
// 	if err != nil {
// 		return c.Status(500).JSON(fiber.Map{"error": "Invalid score format"})
// 	}
// 	fmt.Println("Fingerprint found:", fingerprintID, "with score", score)
// 	return c.JSON(fiber.Map{
// 		"message":        "Fingerprint found",
// 		"fingerprint_id": fingerprintID,
// 		"score":          score,
// 	})
// }

func main() {
	app := fiber.New()

	// Create Redis HNSW index (run only once)
	// _ = rdb.Do(ctx, "FT.CREATE", "fingerprint_index",
	// 	"ON", "HASH",
	// 	"PREFIX", "1", "fingerprint:",
	// 	"SCHEMA", "vector", "VECTOR", "HNSW", "6",
	// 	"TYPE", "FLOAT32", "DIM", "16", "DISTANCE_METRIC", "COSINE").Err()
	_ = rdb.Do(ctx, "FT.CREATE", "fingerprint_index",
		"ON", "HASH",
		"PREFIX", "1", "fingerprint:",
		"SCHEMA", "vector", "VECTOR", "HNSW", "6",
		"TYPE", "FLOAT32", "DIM", "16", "DISTANCE_METRIC", "L2").Err()

	app.Post("/enroll", EnrollFingerprint)
	app.Post("/search", SearchFingerprint)

	log.Println("Server running on :3000")
	log.Fatal(app.Listen(":3000"))
}
