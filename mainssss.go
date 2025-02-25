package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/rand"

	"github.com/redis/go-redis/v9"
)

func mainsss() {
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// Buat fingerprint dengan 512 dimensi dalam format FLOAT32
	fingerprint := make([]byte, 512*4)
	for i := 0; i < 512; i++ {
		binary.LittleEndian.PutUint32(fingerprint[i*4:], math.Float32bits(rand.Float32()))
	}

	// Simpan ke Redis dengan format HASH
	err := rdb.HSet(ctx, "fp:1", "fingerprint", fingerprint).Err()
	if err != nil {
		log.Fatalf("Gagal menyimpan fingerprint: %v", err)
	}

	fmt.Println("Fingerprint berhasil disimpan.")
}
