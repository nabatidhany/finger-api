package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	MQTT "github.com/eclipse/paho.mqtt.golang"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

var (
	ctx = context.Background()
	rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	db *sql.DB
)

// Konfigurasi MQTT
const (
	mqttBroker   = "tcp://3.86.151.127:1883" // Ganti dengan IP Mosquitto
	mqttUser     = "user1"
	mqttPassword = "sholluuser"
)

var mqttClient MQTT.Client

func initDB() {
	var err error
	dsn := "u483254679_shollu:Shollu2025@tcp(185.232.14.52:3306)/u483254679_shollu"
	// dsn := "sholudbuser:sholluuserdb@tcp(3.86.151.127:3306)/db_shollu"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	log.Println("Connected to MySQL!")
}

func initMQTT() {
	opts := MQTT.NewClientOptions()
	opts.AddBroker(mqttBroker)
	opts.SetUsername(mqttUser)
	opts.SetPassword(mqttPassword)
	mqttClient = MQTT.NewClient(opts)

	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		log.Fatalf("Gagal konek ke MQTT: %v", token.Error())
	}
	fmt.Println("Terhubung ke MQTT!")
}

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

func ConvertToVectorV2(fingerprint []byte) []byte {
	if len(fingerprint) < 512 {
		panic("Fingerprint data too short")
	}

	// Konversi fingerprint []byte ke vektor float32 (512 dimensi)
	vector := make([]float32, 512)
	for i := 0; i < 512; i++ {
		vector[i] = float32(fingerprint[i]) / 255.0 // Normalisasi ke [0,1]
	}

	// Encode vektor float32 ke []byte agar bisa disimpan di Redis
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, vector)
	if err != nil {
		log.Println("Error encoding fingerprint vector:", err)
		return nil
	}
	return buf.Bytes()
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

const THRESHOLD = 0.40 // Bisa disesuaikan berdasarkan uji coba

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

func EnrollMode(c *fiber.Ctx) error {
	var data struct {
		IDUser  int `json:"id_user"`
		IDMesin int `json:"id_mesin"`
	}
	if err := c.BodyParser(&data); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	topic := fmt.Sprintf("fingerprint/%d", data.IDMesin)
	message, _ := json.Marshal(map[string]interface{}{
		"id_user": data.IDUser,
		"mode":    "enroll",
	})

	// 🔹 Kirim pesan ke MQTT dengan autentikasi
	token := mqttClient.Publish(topic, 0, false, message)
	token.Wait()

	return c.JSON(fiber.Map{"message": "Enroll request sent"})
}

// New API

func EnrollFingerprintNew(c *fiber.Ctx) error {
	userID := c.Query("user_id")
	if userID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "user_id is required"})
	}

	fingerprintData := c.Body()
	if len(fingerprintData) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No fingerprint data provided"})
	}

	vector := ConvertToVector(fingerprintData)
	vectorString := VectorToString(vector)
	fingerprintID := fmt.Sprintf("fingerprint:%x", md5.Sum(fingerprintData))

	err := rdb.HSet(ctx, fingerprintID, "vector", vectorString).Err()
	if err != nil {
		log.Println("Error saving fingerprint to Redis:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save fingerprint"})
	}

	_, err = db.Exec("INSERT INTO userFinger (user_id, finger_id, created_at) VALUES (?, ?, ?)", userID, fingerprintID, time.Now().UTC())
	if err != nil {
		log.Println("Error inserting fingerprint into MySQL:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save fingerprint in database"})
	}

	return c.JSON(fiber.Map{"message": "Fingerprint enrolled", "id": fingerprintID})
}

func EnrollFingerprintNewV2(c *fiber.Ctx) error {
	userID := c.Query("user_id")
	if userID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "user_id is required"})
	}

	fingerprintData := c.Body()
	if len(fingerprintData) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No fingerprint data provided"})
	}

	vector := ConvertToVectorV2(fingerprintData)
	// vectorString := VectorToString(vector)
	fingerprintID := fmt.Sprintf("fingerprint:%x", md5.Sum(fingerprintData))

	err := rdb.HSet(ctx, fingerprintID, "vector", vector).Err()
	if err != nil {
		log.Println("Error saving fingerprint to Redis:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save fingerprint"})
	}

	_, err = db.Exec("INSERT INTO userFinger (user_id, finger_id, created_at) VALUES (?, ?, ?)", userID, fingerprintID, time.Now().UTC())
	if err != nil {
		log.Println("Error inserting fingerprint into MySQL:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save fingerprint in database"})
	}

	return c.JSON(fiber.Map{"message": "Fingerprint enrolled", "id": fingerprintID})
}

func SaveAbsen(c *fiber.Ctx) error {
	mesinID := c.Query("mesin_id")
	if mesinID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "mesin_id is required"})
	}
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

	if err != nil {
		log.Println("Error searching fingerprint:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to search fingerprint"})
	}

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

	var userID int
	err = db.QueryRow("SELECT user_id FROM userFinger WHERE finger_id = ?", fingerprintID).Scan(&userID)
	if err != nil {
		log.Println("Fingerprint not found in database:", err)
		return c.Status(404).JSON(fiber.Map{"error": "No fingerprint match found"})
	}

	// 🔍 Ambil `fullname` dari tabel `peserta`
	var fullname string
	err = db.QueryRow("SELECT fullname FROM peserta WHERE id = ?", userID).Scan(&fullname)
	if err != nil {
		log.Println("Error retrieving fullname:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to retrieve fullname"})
	}

	_, err = db.Exec("INSERT INTO absensi (user_id, finger_id, jam, mesin_id) VALUES (?, ?, ?, ?)",
		userID, fingerprintID, time.Now().UTC(), mesinID)
	if err != nil {
		log.Println("Error inserting attendance record:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save attendance record"})
	}

	return c.JSON(fiber.Map{
		"message":        "Fingerprint found and attendance recorded",
		"fingerprint_id": fingerprintID,
		"user_id":        userID,
		"fullname":       fullname,
	})
}

// Save yang lebih akurat
func SaveAbsenV2(c *fiber.Ctx) error {
	mesinID := c.Query("mesin_id")
	if mesinID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "mesin_id is required"})
	}
	fingerprintData := c.Body()
	if len(fingerprintData) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No fingerprint data provided"})
	}
	fmt.Println("Fingerprint data:", fingerprintData)

	scannedVector := ConvertToVectorV2(fingerprintData)
	// queryVector := VectorToString(scannedVector)

	rawResult, err := rdb.Do(ctx, "FT.SEARCH", "fingerprint_index_v2",
		"*=>[KNN 1 @vector $query_vector AS score]",
		"PARAMS", "2", "query_vector", scannedVector,
		"SORTBY", "score", "ASC",
		"LIMIT", "0", "1",
		"DIALECT", "2").Result()

	if err != nil {
		log.Println("Error searching fingerprint:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to search fingerprint"})
	}

	log.Printf("Raw search result: %#v\n", rawResult)

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

	var userID int
	err = db.QueryRow("SELECT user_id FROM userFinger WHERE finger_id = ?", fingerprintID).Scan(&userID)
	if err != nil {
		log.Println("Fingerprint not found in database:", err)
		return c.Status(404).JSON(fiber.Map{"error": "No fingerprint match found"})
	}

	// 🔍 Ambil `fullname` dari tabel `peserta`
	var fullname string
	err = db.QueryRow("SELECT fullname FROM peserta WHERE id = ?", userID).Scan(&fullname)
	if err != nil {
		log.Println("Error retrieving fullname:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to retrieve fullname"})
	}

	_, err = db.Exec("INSERT INTO absensi (user_id, finger_id, jam, mesin_id) VALUES (?, ?, ?, ?)",
		userID, fingerprintID, time.Now().UTC(), mesinID)
	if err != nil {
		log.Println("Error inserting attendance record:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save attendance record"})
	}

	return c.JSON(fiber.Map{
		"message":        "Fingerprint found and attendance recorded",
		"fingerprint_id": fingerprintID,
		"user_id":        userID,
		"fullname":       fullname,
	})
}

func SaveAbsenQR(c *fiber.Ctx) error {
	body := struct {
		MesinID string `json:"mesin_id"`
		QRCode  string `json:"qr_code"`
		EventID int    `json:"event_id"`
	}{}

	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if body.MesinID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "mesin_id is required"})
	}

	if body.QRCode == "" {
		return c.Status(400).JSON(fiber.Map{"error": "No QR code data provided"})
	}

	// Optimasi: Gunakan index di kolom qr_code untuk mempercepat pencarian
	var userID int
	var fullname string
	err := db.QueryRow("SELECT id, fullname FROM peserta WHERE qr_code = ?", body.QRCode).Scan(&userID, &fullname)
	if err != nil {
		log.Println("QR Code not found in database:", err)
		return c.Status(404).JSON(fiber.Map{"error": "No matching QR code found"})
	}

	_, err = db.Exec("INSERT INTO absensi (user_id, finger_id, jam, mesin_id, event_id) VALUES (?, ?, ?, ?, ?)",
		userID, body.QRCode, time.Now().UTC(), body.MesinID, body.EventID)
	if err != nil {
		log.Println("Error inserting attendance record:", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save attendance record"})
	}

	return c.JSON(fiber.Map{
		"message":  "QR Code found and attendance recorded",
		"qr_code":  body.QRCode,
		"user_id":  userID,
		"fullname": fullname,
		"event_id": body.EventID,
	})
}

func ApiKeyMiddleware(c *fiber.Ctx) error {
	apiKey := c.Get("X-API-Key")          // Ambil API Key dari header
	validApiKey := "shollusemakindidepan" // Ganti dengan API Key yang aman

	if apiKey != validApiKey {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden: Invalid API Key"})
	}
	return c.Next()
}

func main() {
	app := fiber.New()
	initMQTT()
	initDB()

	// _ = rdb.Do(ctx, "FT.CREATE", "fingerprint_index",
	// 	"ON", "HASH",
	// 	"PREFIX", "1", "fingerprint:",
	// 	"SCHEMA", "vector", "VECTOR", "HNSW", "6",
	// 	"TYPE", "FLOAT32", "DIM", "16", "DISTANCE_METRIC", "L2").Err()

	_ = rdb.Do(ctx, "FT.CREATE", "fingerprint_index_v2",
		"ON", "HASH",
		"PREFIX", "1", "fingerprint:",
		"SCHEMA", "vector", "VECTOR", "HNSW", "6",
		"TYPE", "FLOAT32", "DIM", "512", "DISTANCE_METRIC", "L2").Err()

	app.Post("/enroll", EnrollFingerprint)
	app.Post("/search", SearchFingerprint)

	// new API
	api := app.Group("/api/v1")
	api.Post("/enroll", ApiKeyMiddleware, EnrollFingerprintNew)
	api.Post("/absent", ApiKeyMiddleware, SaveAbsen)
	api.Post("/absent-qr", ApiKeyMiddleware, SaveAbsenQR)
	api.Post("/enroll-mode", ApiKeyMiddleware, EnrollMode)

	apiV2 := app.Group("/api/v2")
	apiV2.Post("/enroll", ApiKeyMiddleware, EnrollFingerprintNewV2)
	apiV2.Post("/absent", ApiKeyMiddleware, SaveAbsenV2)

	log.Println("Server running on :3000")
	log.Fatal(app.Listen(":3000"))
}
