package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

// --- KONFIGURASI TELEGRAM & SECURITY ---
const (
	TELEGRAM_BOT_TOKEN = "8574666027:AAE4Jl2oTOO1Pcz-LV2uXspuqgtNtO8LHZs"
	TELEGRAM_CHAT_ID   = "1350800708"
	// Secret Key Kriptografi untuk JWT (Di production, gunakan Environment Variable)
	JWT_SECRET_KEY     = "Dwansoft_SecOps_SuperSecretKey_2026" 
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

var (
	db       *sql.DB
	dbMutex  sync.Mutex
	upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	APP_PORT string
	DB_PORT  string

	currentAuthLogs []AuthLog
	logMutex        sync.Mutex
	
	cpuAlertThreshold = 90.0
	ramAlertThreshold = 95.0
	thresholdMutex    sync.Mutex
)

// --- STRUCT DATA ---
type ClientMessage struct {
	Type      string  `json:"type"`
	Threshold float64 `json:"threshold"`
}

type AuthLog struct {
	Time    string `json:"time"`
	User    string `json:"user"`
	IP      string `json:"ip"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type SystemStats struct {
	ServerName       string    `json:"serverName"`
	Platform         string    `json:"platform"`
	Kernel           string    `json:"kernel"`
	CPUModel         string    `json:"cpuModel"`
	Uptime           uint64    `json:"uptime"`
	CPUUsage         float64   `json:"cpuUsage"`
	RamUsed          uint64    `json:"ramUsed"`
	RamTotal         uint64    `json:"ramTotal"`
	RamPercent       float64   `json:"ramPercent"`
	DiskUsed         uint64    `json:"diskUsed"`
	DiskTotal        uint64    `json:"diskTotal"`
	DiskPercent      float64   `json:"diskPercent"`
	DBStatus         string    `json:"dbStatus"`
	DBActiveConn     int       `json:"dbActiveConn"`
	DBMaxConn        int       `json:"dbMaxConn"`
	AuthLogs         []AuthLog `json:"authLogs"`
	CurrentThreshold float64   `json:"currentThreshold"`
}

// --- FUNGSI GENERATE & VALIDASI JWT ---
func generateAdminToken() (string, error) {
	// Token di-set berlaku sangat lama (misal 5 tahun) karena untuk HP Bos
	expirationTime := time.Now().Add(5 * 365 * 24 * time.Hour)
	claims := &jwt.RegisteredClaims{
		Subject:   "admin_dwansoft_mobile",
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(JWT_SECRET_KEY))
	return tokenString, err
}

func validateToken(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Pastikan algoritma yang digunakan sesuai
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(JWT_SECRET_KEY), nil
	})

	if err != nil {
		return false
	}
	return token.Valid
}

// --- FUNGSI LAINNYA ---
func sendTelegramAlert(message string) {
	fmt.Println("📧 ALERT TELEGRAM DIKIRIM:\n", message)
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TELEGRAM_BOT_TOKEN)
	data := url.Values{}
	data.Set("chat_id", TELEGRAM_CHAT_ID)
	data.Set("text", message)
	data.Set("parse_mode", "Markdown")

	go func() {
		resp, err := http.PostForm(apiURL, data)
		if err != nil {
			log.Println("[ERROR] Gagal koneksi ke API Telegram:", err)
			return
		}
		defer resp.Body.Close()
	}()
}

func initHistoricalDB() {
	query := `CREATE TABLE IF NOT EXISTS metric_history (
		id SERIAL PRIMARY KEY,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		cpu_usage FLOAT,
		ram_usage FLOAT,
		disk_usage FLOAT,
		active_connections INT,
		event_type VARCHAR(100)
	);`
	dbMutex.Lock()
	if db != nil { db.Exec(query) }
	dbMutex.Unlock()
}

func saveHistoricalData(cpuVal, ramVal, diskVal float64, dbConn int, eventType string) {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if db != nil {
		db.Exec("INSERT INTO metric_history (cpu_usage, ram_usage, disk_usage, active_connections, event_type) VALUES ($1, $2, $3, $4, $5)", cpuVal, ramVal, diskVal, dbConn, eventType)
	}
}

func runAgentLogScanner() {
	var lastSshLogContent string
	hostStat, _ := host.Info()
	fmt.Println("[INFO] Agent: SSH Log Scanner Aktif (Mode Real-Time Zero Tolerance)...")

	for {
		cmd := exec.Command("journalctl", "-u", "ssh", "-n", "5", "--no-pager")
		out, err := cmd.Output()
		var newLogs []AuthLog

		if err == nil {
			lines := strings.Split(string(out), "\n")
			reFailed := regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+)`)
			reAccept := regexp.MustCompile(`Accepted password for (\S+) from (\S+)`)

			for _, line := range lines {
				if line == "" || line == lastSshLogContent { 
					continue 
				}
				
				var logEntry AuthLog
				if len(line) > 15 { 
					logEntry.Time = line[:15] 
				} else { 
					logEntry.Time = time.Now().Format("15:04:05") 
				}

				// DETEKSI ZERO TOLERANCE: Setiap ada gagal login, langsung kirim alert
				if matches := reFailed.FindStringSubmatch(line); len(matches) > 0 {
					logEntry.Status = "FAILED"
					logEntry.User = matches[1]
					logEntry.IP = matches[2]
					logEntry.Message = "Percobaan Akses Ilegal"
					newLogs = append(newLogs, logEntry)

					// Ambil metrik terkini saat terjadi serangan
					c, _ := cpu.Percent(0, false)
					v, _ := mem.VirtualMemory()
					d, _ := disk.Usage("/")
					cpuVal := 0.0
					if len(c) > 0 { cpuVal = c[0] }
					_, dbConn, _ := getDBStats()

					msg := fmt.Sprintf("🔥 *ANOMALI KEAMANAN TERDETEKSI* 🔥\n\n"+
						"🥷 *IP Attacker:* `%s`\n"+
						"⏱️ *Timestamp:* %s\n\n"+
						"📊 *Metrics Terkini (%s):*\n"+
						" - CPU Usage: %.1f%%\n"+
						" - RAM Usage: %.1f%%\n"+
						" - Disk Usage: %.1f%%\n"+
						" - DB Active Conn: %d\n\n"+
						"⚠️ *Detail Anomali:*\n"+
						" - 🔺 SSH Brute Force Attempt (Target: `%s`)",
						logEntry.IP, time.Now().Format("2006-01-02 15:04:05"), hostStat.Hostname, cpuVal, v.UsedPercent, d.UsedPercent, dbConn, logEntry.User)

					sendTelegramAlert(msg)
					saveHistoricalData(cpuVal, v.UsedPercent, 0, 0, "SINGLE_FAILED_LOGIN")
					
					lastSshLogContent = line // Update log terakhir agar tidak double-alert
					
				} else if matches := reAccept.FindStringSubmatch(line); len(matches) > 0 {
					logEntry.Status = "ACCEPTED"
					logEntry.User = matches[1]
					logEntry.IP = matches[2]
					logEntry.Message = "Login Berhasil"
					newLogs = append(newLogs, logEntry)
					
					lastSshLogContent = line
				}
			}
		}

		if len(newLogs) > 0 {
			logMutex.Lock()
			currentAuthLogs = append(newLogs, currentAuthLogs...)
			if len(currentAuthLogs) > 10 { 
				currentAuthLogs = currentAuthLogs[:10] 
			}
			logMutex.Unlock()
		}
		
		time.Sleep(2 * time.Second) 
	}
}

func runCentralBackend() {
	var lastAlertTime time.Time
	hostStat, _ := host.Info()
	fmt.Println("[INFO] Backend: Pemroses Anomali & Sinkronisasi Database Aktif...")

	for {
		c, _ := cpu.Percent(time.Second, false); v, _ := mem.VirtualMemory(); d, _ := disk.Usage("/")
		cpuVal := 0.0; if len(c) > 0 { cpuVal = c[0] }
		_, dbConn, dbMax := getDBStats()

		if time.Now().Second() == 0 { saveHistoricalData(cpuVal, v.UsedPercent, d.UsedPercent, dbConn, "ROUTINE_METRICS") }

		thresholdMutex.Lock(); cLimit := cpuAlertThreshold; rLimit := ramAlertThreshold; thresholdMutex.Unlock()

		anomaliTerjadi := false; pesanAnomali := ""

		if cpuVal > cLimit { anomaliTerjadi = true; pesanAnomali += fmt.Sprintf(" - 🔺 CPU Load: %.1f%% (Limit: %.0f%%)\n", cpuVal, cLimit) }
		if v.UsedPercent > rLimit { anomaliTerjadi = true; pesanAnomali += fmt.Sprintf(" - 🔺 RAM Critical: %.1f%% (Limit: %.0f%%)\n", v.UsedPercent, rLimit) }
		if d.UsedPercent > 90.0 { anomaliTerjadi = true; pesanAnomali += fmt.Sprintf(" - 🔺 Disk Abnormal: %.1f%% Full\n", d.UsedPercent) }
		if dbMax > 0 && dbConn > int(float64(dbMax)*0.8) { anomaliTerjadi = true; pesanAnomali += fmt.Sprintf(" - 🔺 DB Conn Spike: %d/%d Active\n", dbConn, dbMax) }

		if anomaliTerjadi && time.Since(lastAlertTime) > 30*time.Second {
			msg := fmt.Sprintf("🔥 *ANOMALI RESOURCE TERDETEKSI* 🔥\n\n"+
				"🥷 *IP Attacker:* N/A (System Load)\n"+
				"⏱️ *Timestamp:* %s\n\n"+
				"📊 *Metrics Terkini (%s):*\n"+
				" - CPU Usage: %.1f%%\n"+
				" - RAM Usage: %.1f%%\n"+
				" - Disk Usage: %.1f%%\n"+
				" - DB Active Conn: %d\n\n"+
				"⚠️ *Detail Anomali:*\n%s",
				time.Now().Format("2006-01-02 15:04:05"), hostStat.Hostname, cpuVal, v.UsedPercent, d.UsedPercent, dbConn, pesanAnomali)

			sendTelegramAlert(msg)
			saveHistoricalData(cpuVal, v.UsedPercent, d.UsedPercent, dbConn, "RESOURCE_ANOMALY")
			lastAlertTime = time.Now()
		}
		time.Sleep(1 * time.Second) 
	}
}

func connectDB() {
	dbMutex.Lock(); defer dbMutex.Unlock()
	dbHost := "localhost"; dbUser := getEnv("DB_USER", "yongki"); dbPass := getEnv("DB_PASS", "password123"); dbName := getEnv("DB_NAME", "siabas_db"); portInt, _ := strconv.Atoi(DB_PORT)
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", dbHost, portInt, dbUser, dbPass, dbName)
	var err error; db, err = sql.Open("postgres", psqlInfo)
	if err == nil { db.Ping() }
}

func dbWatchdog() {
	time.Sleep(2 * time.Second); connectDB(); initHistoricalDB()
	for {
		time.Sleep(5 * time.Second)
		dbMutex.Lock()
		if db != nil { if err := db.Ping(); err != nil { db.Close(); db = nil } }
		dbMutex.Unlock()
		if db == nil { connectDB() }
	}
}

func getDBStats() (string, int, int) {
	dbMutex.Lock(); localDB := db; dbMutex.Unlock()
	if localDB == nil { return "Connecting...", 0, 100 }
	if err := localDB.Ping(); err != nil { return "DOWN", 0, 100 }
	activeConn := 0; _ = localDB.QueryRow("SELECT count(*) FROM pg_stat_activity WHERE state = 'active'").Scan(&activeConn)
	maxConn := 100; var maxConnStr string; _ = localDB.QueryRow("SHOW max_connections").Scan(&maxConnStr)
	if maxConnStr != "" { maxConn, _ = strconv.Atoi(maxConnStr) }
	return "Connected", activeConn, maxConn
}

// --- WEBSOCKET HANDLER DENGAN JWT VERIFICATION ---
func wsHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Ekstrak Token dari URL Param (Contoh: ws://localhost:8080/ws?token=eyJ...)
	tokenString := r.URL.Query().Get("token")
	
	// 2. Validasi Kriptografi Token
	if tokenString == "" || !validateToken(tokenString) {
		log.Println("[SECURITY] Koneksi ditolak: JWT Token tidak valid atau kosong dari IP:", r.RemoteAddr)
		http.Error(w, "Unauthorized: Invalid or Missing JWT Token", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil { return }
	defer conn.Close()

	hostStat, _ := host.Info(); cpuStat, _ := cpu.Info()
	cpuModelName := "Unknown CPU"; if len(cpuStat) > 0 { cpuModelName = cpuStat[0].ModelName }

	go func() {
		for {
			_, message, err := conn.ReadMessage()
			if err != nil { break }
			var msg ClientMessage
			if err := json.Unmarshal(message, &msg); err == nil {
				if msg.Type == "THRESHOLD" && msg.Threshold > 0 {
					thresholdMutex.Lock(); cpuAlertThreshold = msg.Threshold; thresholdMutex.Unlock()
				}
				if msg.Type == "MANUAL_TRIGGER" {
					c, _ := cpu.Percent(0, false); v, _ := mem.VirtualMemory(); d, _ := disk.Usage("/"); cpuVal := 0.0; if len(c) > 0 { cpuVal = c[0] }
					_, dbConn, _ := getDBStats()
					
					alertMsg := fmt.Sprintf("🔥 *PENGUJIAN SISTEM NOTIFIKASI* 🔥\n\n"+
						"🥷 *IP Attacker:* N/A (Manual Trigger)\n"+
						"⏱️ *Timestamp:* %s\n\n"+
						"📊 *Metrics Terkini (%s):*\n"+
						" - CPU Usage: %.1f%%\n"+
						" - RAM Usage: %.1f%%\n"+
						" - Disk Usage: %.1f%%\n"+
						" - DB Active Conn: %d\n\n"+
						"⚠️ *Detail Anomali:*\n"+
						" - 🔺 Administrator menguji fungsi EWS ke Telegram.",
						time.Now().Format("2006-01-02 15:04:05"), hostStat.Hostname, cpuVal, v.UsedPercent, d.UsedPercent, dbConn)
					sendTelegramAlert(alertMsg)
				}
			}
		}
	}()

	for {
		v, _ := mem.VirtualMemory(); c, _ := cpu.Percent(time.Second, false); d, _ := disk.Usage("/"); h_realtime, _ := host.Info()
		cpuVal := 0.0; if len(c) > 0 { cpuVal = c[0] }
		dbStatus, dbConn, dbMax := getDBStats()

		logMutex.Lock(); logsToSend := make([]AuthLog, len(currentAuthLogs)); copy(logsToSend, currentAuthLogs); logMutex.Unlock()
		thresholdMutex.Lock(); currentLimit := cpuAlertThreshold; thresholdMutex.Unlock()

		fullStats := SystemStats{
			ServerName: hostStat.Hostname, Platform: hostStat.Platform, Kernel: hostStat.KernelVersion, CPUModel: cpuModelName, Uptime: h_realtime.Uptime,
			CPUUsage: cpuVal, RamUsed: v.Used, RamTotal: v.Total, RamPercent: v.UsedPercent, DiskUsed: d.Used, DiskTotal: d.Total, DiskPercent: d.UsedPercent,
			DBStatus: dbStatus, DBActiveConn: dbConn, DBMaxConn: dbMax, AuthLogs: logsToSend, CurrentThreshold: currentLimit,
		}
		jsonMsg, _ := json.Marshal(fullStats)
		if err := conn.WriteMessage(websocket.TextMessage, jsonMsg); err != nil { break }
	}
}

func main() {
	// --- FITUR COMMAND LINE UNTUK GENERATE TOKEN BOS ---
	generateToken := flag.Bool("generate-token", false, "Buat JWT Token baru untuk Mobile App Bos")
	flag.Parse()

	if *generateToken {
		token, err := generateAdminToken()
		if err != nil {
			log.Fatalf("Gagal membuat token: %v", err)
		}
		fmt.Println("\n=======================================================")
		fmt.Println("🔑 JWT TOKEN BERHASIL DIBUAT (Berlaku 5 Tahun)")
		fmt.Println("=======================================================")
		fmt.Println(token)
		fmt.Println("=======================================================")
		fmt.Println("Cara penggunaan di aplikasi React Native Anda:")
		fmt.Println("ws://<IP_SERVER>:8080/ws?token=" + token)
		fmt.Println("=======================================================\n")
		return 
	}

	// --- LOGIKA UTAMA SERVER ---
	APP_PORT = getEnv("PORT", "8080")
	DB_PORT = getEnv("DB_PORT", "5432")

	go dbWatchdog()         
	go runAgentLogScanner() 
	go runCentralBackend()  

	startupMsg := "✅ *SYSTEM ONLINE*\nMenunggu metrik dari PT Dwansoft Global ID..."
	sendTelegramAlert(startupMsg)

	http.HandleFunc("/ws", wsHandler)
	fmt.Printf("[INFO] Layanan WebSocket Backend berjalan pada port :%s\n", APP_PORT)
	log.Fatal(http.ListenAndServe(":"+APP_PORT, nil))
}
