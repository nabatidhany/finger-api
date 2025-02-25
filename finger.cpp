#include <Adafruit_Fingerprint.h>
#include <SoftwareSerial.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

#define BUZZER_PIN 13  
#define OLED_SDA 4  
#define OLED_SCL 5  
#define SERVER_ENROLL "http://192.168.1.5:3000/enroll" 
#define SERVER_SEARCH "http://192.168.1.5:3000/search"
#define WIFI_SSID "Dhanyla"
#define WIFI_PASSWORD "20230303"

Adafruit_SSD1306 display(128, 64, &Wire, -1);
SoftwareSerial mySerial(14, 12);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);

int mode = 2;  // Default mode Standby

void setup() {
    Serial.begin(115200);
    mySerial.begin(57600);
    pinMode(BUZZER_PIN, OUTPUT);
    
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    Serial.print("Menghubungkan ke WiFi");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nTerhubung ke WiFi");
    
    Wire.begin(OLED_SDA, OLED_SCL);
    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
        Serial.println("Gagal menginisialisasi OLED");
        while (1);
    }
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(WHITE);

    tampilkanPesan("Inisialisasi Sensor...");
    delay(2000);

    Serial.println("Menginisialisasi sensor sidik jari...");
    finger.begin(57600);
    // finger.begin(57600);

    if (finger.verifyPassword()) {
        Serial.println("Sensor AS608 terdeteksi!");
        tampilkanPesan("Sensor OK!");
    } else {
        Serial.println("Sensor tidak ditemukan!");
        tampilkanPesan("Sensor ERROR!");
        while (1);
    }

    tampilkanPesan("Mode: Standby");
}

void loop() {
    if (Serial.available()) {
        int input = Serial.parseInt();
        if (input == 1 || input == 2) {
            mode = input;
            Serial.print("Mode diubah ke: ");
            Serial.println(mode);
        } else {
            Serial.println("Mode tidak valid! Pilih 1 atau 2.");
        }
    }

    if (mode == 1) {
        handleEnroll();
    } else if (mode == 2) {
        handleStandby();
    }
}

void handleEnroll() {
    tampilkanPesan("Letakkan jari...");
    if (!waitForFinger()) return;
    if (!captureFingerprint(1)) return;
    successTone(1);
    
    tampilkanPesan("Mengirim data...");
    downloadFingerprintTemplate(SERVER_ENROLL);

    mode = 2;  // Kembali ke Standby
    tampilkanPesan("Mode: Standby");
    delay(3000);
}


void handleStandby() {
    tampilkanPesan("Letakkan jari...");
    if (!waitForFinger()) return;
    if (!captureFingerprint(1)) return;
    successTone(1);
    tampilkanPesan("Mengirim data...");
    downloadFingerprintTemplate(SERVER_SEARCH);

    mode = 2;  // Kembali ke Standby
    tampilkanPesan("Mode: Standby");
    delay(3000);
}

bool waitForFinger() {
    int timeout = 10000;
    uint32_t start = millis();
    while ((millis() - start) < timeout) {
        int p = finger.getImage();
        if (p == FINGERPRINT_OK) {
            Serial.println("Jari terdeteksi!");
            tampilkanPesan("Jari terdeteksi!");
            return true;
        }
        delay(100);
    }
    Serial.println("Timeout: Tidak ada jari.");
    tampilkanPesan("Gagal! Coba lagi.");
    return false;
}

bool captureFingerprint(uint8_t bufferID) {
    int p = finger.image2Tz(bufferID);
    if (p != FINGERPRINT_OK) {
        Serial.println("Gagal capture sidik jari.");
        failureTone();
        tampilkanPesan("Gagal capture!");
        return false;
    }
    Serial.print("Sidik jari ke Buffer ");
    Serial.println(bufferID);
    tampilkanPesan("Sidik jari OK!");
    return true;
}

void downloadFingerprintTemplate(const char *serverUrl) {
    Serial.println("------------------------------------");

    uint8_t p = finger.getModel();
    if (p != FINGERPRINT_OK) {
        Serial.println("Gagal mengambil template sidik jari.");
        return;
    }

    Serial.println("Template berhasil diambil. Menampilkan data HEX:");

    uint8_t bytesReceived[534];  
    memset(bytesReceived, 0xff, 534);

    uint32_t starttime = millis();
    int i = 0;
    while (i < 534 && (millis() - starttime) < 5000) {  
        if (mySerial.available()) {
            bytesReceived[i++] = mySerial.read();
        }
    }
    
    Serial.print(i);
    Serial.println(" bytes read.");


    Serial.println("Data mentah yang diterima dari sensor:");
    for (int j = 0; j < 534; ++j) {
        Serial.print(bytesReceived[j], HEX);
        Serial.print(" ");
    }
    Serial.println("\nSelesai menampilkan data mentah.");


    uint8_t fingerTemplate[512];  
    memset(fingerTemplate, 0xff, 512);

    int uindx = 9, index = 0;
    memcpy(fingerTemplate + index, bytesReceived + uindx, 256);
    uindx += 256;
    uindx += 2;
    uindx += 9;
    index += 256;
    memcpy(fingerTemplate + index, bytesReceived + uindx, 256);

    Serial.println("Data template finger setelah diproses.");
    for (int j = 0; j < 512; ++j) {
        Serial.print(fingerTemplate[j], HEX);
        Serial.print(" ");
    }
    Serial.println("\nTemplate sidik jari selesai ditampilkan.");

    // **Mengirim template ke server**
    Serial.println("Mengirim template ke server...");

    WiFiClient client;
    HTTPClient http;
    http.begin(client, serverUrl);
    http.addHeader("Content-Type", "application/octet-stream");
    Serial.println("Template yuang akan dikirimkan.");

    int httpResponseCode = http.POST(fingerTemplate, 512);

    if (httpResponseCode > 0) {
        Serial.print("Template berhasil dikirim! HTTP Response: ");
        Serial.println(httpResponseCode);
    } else {
        Serial.print("Gagal mengirim template. HTTP Response: ");
        Serial.println(httpResponseCode);
    }

    http.end();
}

void tampilkanPesan(const char *pesan) {
    display.clearDisplay();
    display.setCursor(10, 25);
    display.print(pesan);
    display.display();
}

void successTone(uint8_t step) {
    tone(BUZZER_PIN, 400 + (step * 100), 200);
}

void failureTone() {
    tone(BUZZER_PIN, 700, 100);
    delay(150);
    tone(BUZZER_PIN, 500, 100);
    delay(150);
    tone(BUZZER_PIN, 300, 100);
}