package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ===================================================================================
//
//                                  ESTRUCTURAS DE DATOS
//
// ===================================================================================

// Device representa un dispositivo individual descubierto en la red.
type Device struct {
	IP          string        `json:"ip"`
	MAC         string        `json:"mac"`
	Vendor      string        `json:"vendor"`
	Hostname    string        `json:"hostname"`
	OS          string        `json:"os"`
	OpenPorts   []PortInfo    `json:"open_ports"`
	Services    []ServiceInfo `json:"services"`
	Vulnerable  bool          `json:"vulnerable"`
	LastSeen    time.Time     `json:"last_seen"`
	Responsive  bool          `json:"responsive"`
	DeviceType  string        `json:"device_type"`
	RiskLevel   int           `json:"risk_level"`
	LastScan    time.Duration `json:"last_scan_duration"`
	Notes       string        `json:"notes"` // Campo para notas manuales
	Fingerprint OSFingerprint `json:"os_fingerprint"`
}

// PortInfo contiene información sobre un puerto escaneado.
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
}

// ServiceInfo detalla un servicio que se ejecuta en un puerto.
type ServiceInfo struct {
	Port    int    `json:"port"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Banner  string `json:"banner"`
}

// ScanResult agrupa los resultados de un escaneo completo.
type ScanResult struct {
	Timestamp time.Time `json:"timestamp"`
	Devices   []Device  `json:"devices"`
	Network   string    `json:"network"`
	ScanTime  string    `json:"scan_time"`
}

// Vulnerability define una vulnerabilidad conocida.
type Vulnerability struct {
	CVE         string   `json:"cve"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Affected    []string `json:"affected_products"`
	Reference   string   `json:"reference"`
}

// OSFingerprint almacena datos para la identificación del SO.
type OSFingerprint struct {
	TTL        int      `json:"ttl"`
	WindowSize int      `json:"window_size"`
	Signatures []string `json:"signatures"`
}

// ===================================================================================
//
//                                  CONFIGURACIÓN GLOBAL
//
// ===================================================================================

// Config define todos los parámetros de configuración del escáner.
type Config struct {
	Timeout         string        `json:"timeout"`
	Threads         int           `json:"threads"`
	FastMode        bool          `json:"fast_mode"`
	DeepScan        bool          `json:"deep_scan"`
	VulnScan        bool          `json:"vuln_scan"`
	AutoSave        bool          `json:"auto_save"`
	OutputFileJSON  string        `json:"output_file_json"`
	OutputFileCSV   string        `json:"output_file_csv"`
	OutputFileHTML  string        `json:"output_file_html"`
	OutputFileDOT   string        `json:"output_file_dot"`
	LogFile         string        `json:"log_file"`
	MaxDevices      int           `json:"max_devices"`
	NetworkRange    string        `json:"network_range"`
	RescanInterval  string        `json:"rescan_interval"`
	AlertThreshold  int           `json:"alert_threshold"`
	OUIDatabasePath string        `json:"oui_database_path"`
	VulnDBPath      string        `json:"vuln_db_path"`
	PortProfiles    map[string][]int `json:"port_profiles"`
	ActiveProfile   string        `json:"active_port_profile"`
}

var (
	// Variables globales para el estado de la aplicación.
	activeDevices   = make(map[string]Device)
	deviceMutex     sync.RWMutex
	arpCache        = make(map[string]string)
	ouiDatabase     = make(map[string]string)
	vulnerabilities []Vulnerability
	scanConfig      Config
	appLogger       *log.Logger
)

// ===================================================================================
//
//                                  FUNCIÓN PRINCIPAL (MAIN)
//
// ===================================================================================

func main() {
	// Inicialización de la aplicación.
	if err := loadConfiguration("config.json"); err != nil {
		log.Fatalf("Error fatal: No se pudo cargar la configuración: %v", err)
	}

	setupLogger()
	appLogger.Println("Aplicación iniciada.")

	if err := loadOUIDatabase(); err != nil {
		appLogger.Printf("Advertencia: No se pudo cargar la base de datos OUI: %v", err)
	}

	if err := loadVulnerabilityDB(); err != nil {
		appLogger.Printf("Advertencia: No se pudo cargar la base de datos de vulnerabilidades: %v", err)
	}

	loadARPCache()
	initializeScanner()

	if scanConfig.NetworkRange == "" {
		scanConfig.NetworkRange = getNetworkRange()
		if scanConfig.NetworkRange == "" {
			appLogger.Fatalln("Error fatal: No se pudo determinar el rango de la red.")
			return
		}
		appLogger.Printf("Rango de red detectado automáticamente: %s", scanConfig.NetworkRange)
	}

	displayWelcomeMessage()

	// Iniciar el escaneo continuo en segundo plano.
	go continuousScanner()

	// Iniciar el panel de control interactivo.
	startControlPanel()
}

// displayWelcomeMessage muestra un banner de bienvenida al iniciar.
func displayWelcomeMessage() {
	fmt.Println("=====================================================")
	fmt.Println("==   Escáner de Red Avanzado en Go                 ==")
	fmt.Println("=====================================================")
	fmt.Println("Iniciando escaneo automático...")
	fmt.Println("Rango de red:", scanConfig.NetworkRange)
	fmt.Println("Parámetros:")
	timeout, _ := time.ParseDuration(scanConfig.Timeout)
	fmt.Printf("  Hilos: %d | Timeout: %v | Perfil de Puertos: %s\n",
		scanConfig.Threads, timeout, scanConfig.ActiveProfile)
	fmt.Printf("  Escaneo profundo: %v | Escaneo de vulnerabilidades: %v\n",
		scanConfig.DeepScan, scanConfig.VulnScan)
	fmt.Println("Presione Ctrl+C para detener la aplicación.")
	fmt.Println("-----------------------------------------------------")
}

// ===================================================================================
//
//                                  MÓDULO DE CONFIGURACIÓN
//
// ===================================================================================

// loadConfiguration carga la configuración desde un archivo JSON.
func loadConfiguration(file string) error {
	configFile, err := os.Open(file)
	if err != nil {
		// Si no existe, crea una configuración por defecto.
		if os.IsNotExist(err) {
			return createDefaultConfig(file)
		}
		return err
	}
	defer configFile.Close()

	decoder := json.NewDecoder(configFile)
	return decoder.Decode(&scanConfig)
}

// createDefaultConfig genera un archivo de configuración por defecto.
func createDefaultConfig(file string) error {
	defaultConfig := Config{
		Timeout:         "2s",
		Threads:         150,
		FastMode:        false,
		DeepScan:        true,
		VulnScan:        true,
		AutoSave:        true,
		OutputFileJSON:  "scan_results.json",
		OutputFileCSV:   "scan_results.csv",
		OutputFileHTML:  "scan_report.html",
		OutputFileDOT:   "network_map.dot",
		LogFile:         "scanner.log",
		MaxDevices:      512,
		NetworkRange:    "",
		RescanInterval:  "5m",
		AlertThreshold:  8,
		OUIDatabasePath: "oui.txt",
		VulnDBPath:      "vulnerabilities.json",
		PortProfiles: map[string][]int{
			"quick": {21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080, 8443},
			"full":  generatePortRange(1, 1024),
			"web":   {80, 443, 8000, 8080, 8443, 3000},
		},
		ActiveProfile: "quick",
	}
	scanConfig = defaultConfig // Usar la configuración por defecto
	fileData, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, fileData, 0644)
}

// setupLogger inicializa el sistema de registro de la aplicación.
func setupLogger() {
	file, err := os.OpenFile(scanConfig.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	appLogger = log.New(file, "SCANNER: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// ===================================================================================
//
//                                  MÓDULO DE INICIALIZACIÓN
//
// ===================================================================================

// initializeScanner ajusta la configuración basada en el entorno.
func initializeScanner() {
	// Ajustes específicos del sistema operativo.
	switch runtime.GOOS {
	case "windows":
		if scanConfig.Threads > 150 {
			scanConfig.Threads = 150
		}
	case "linux":
		if scanConfig.Threads > 250 {
			scanConfig.Threads = 250
		}
	}
	if isRaspberryPi() {
		scanConfig.Threads = 50
		scanConfig.FastMode = true
		appLogger.Println("Detectada Raspberry Pi, aplicando configuración de bajo consumo.")
	}
}

// isRaspberryPi comprueba si el programa se ejecuta en una Raspberry Pi.
func isRaspberryPi() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	content, err := ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	return strings.Contains(string(content), "Raspberry Pi")
}

// loadVulnerabilityDB carga la base de datos de vulnerabilidades.
func loadVulnerabilityDB() error {
	file, err := os.Open(scanConfig.VulnDBPath)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	return decoder.Decode(&vulnerabilities)
}

// loadOUIDatabase carga los prefijos de MAC y fabricantes.
func loadOUIDatabase() error {
	file, err := os.Open(scanConfig.OUIDatabasePath)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) >= 2 {
			prefix := strings.ReplaceAll(parts[0], "-", "")
			ouiDatabase[prefix] = parts[1]
		}
	}
	return scanner.Err()
}

// loadARPCache precarga la caché ARP del sistema.
func loadARPCache() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd = exec.Command("arp", "-a")
	case "windows":
		cmd = exec.Command("arp", "-a")
	default:
		return
	}
	output, err := cmd.Output()
	if err != nil {
		appLogger.Printf("Error al cargar la caché ARP: %v", err)
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		var ip, mac string
		if runtime.GOOS == "windows" {
			if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
				ip, mac = fields[0], fields[1]
			}
		} else {
			if len(fields) >= 4 {
				ip, mac = strings.Trim(fields[1], "()"), fields[3]
			}
		}
		if ip != "" && mac != "" {
			arpCache[ip] = mac
		}
	}
	appLogger.Printf("Caché ARP cargada con %d entradas.", len(arpCache))
}

// ===================================================================================
//
//                                  MÓDULO DE RED
//
// ===================================================================================

// getNetworkRange intenta determinar el rango de red local.
func getNetworkRange() string {
	ip := getLocalIP()
	if ip == "" {
		return ""
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
}

// getLocalIP obtiene la dirección IP local no loopback.
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

// ===================================================================================
//
//                                  MÓDULO DE ESCANEO PRINCIPAL
//
// ===================================================================================

// continuousScanner ejecuta ciclos de escaneo a intervalos regulares.
func continuousScanner() {
	interval, err := time.ParseDuration(scanConfig.RescanInterval)
	if err != nil {
		appLogger.Printf("Intervalo de escaneo inválido, usando 5m por defecto. Error: %v", err)
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		performScanCycle()
		select {
		case <-ticker.C:
			// El ticker controla el próximo ciclo
		}
	}
}

// performScanCycle ejecuta una ronda completa de escaneo y procesamiento.
func performScanCycle() {
	appLogger.Println("Iniciando nuevo ciclo de escaneo...")
	startTime := time.Now()
	results := scanNetwork(scanConfig.NetworkRange)
	elapsed := time.Since(startTime)

	deviceMutex.Lock()
	for _, device := range results {
		device.LastScan = elapsed.Round(time.Millisecond)
		if existing, found := activeDevices[device.IP]; found {
			// Actualizar dispositivo existente
			existing.OpenPorts, existing.Services, existing.Vulnerable = device.OpenPorts, device.Services, device.Vulnerable
			existing.LastSeen, existing.RiskLevel = time.Now(), calculateRiskLevel(existing)
			activeDevices[device.IP] = existing
		} else {
			// Agregar nuevo dispositivo
			device.LastSeen = time.Now()
			device.RiskLevel = calculateRiskLevel(device)
			activeDevices[device.IP] = device
			appLogger.Printf("Nuevo dispositivo descubierto: %s (%s)", device.IP, device.Vendor)
		}
	}

	cleanupInactiveDevices()
	checkSecurityAlerts()
	deviceMutex.Unlock()

	if scanConfig.AutoSave {
		saveAllResults()
	}
	appLogger.Printf("Ciclo de escaneo completado en %v. Dispositivos activos: %d", elapsed, len(results))
}

// cleanupInactiveDevices elimina dispositivos que no han sido vistos en mucho tiempo.
func cleanupInactiveDevices() {
	interval, _ := time.ParseDuration(scanConfig.RescanInterval)
	for ip, device := range activeDevices {
		if time.Since(device.LastSeen) > interval*3 {
			delete(activeDevices, ip)
			appLogger.Printf("Dispositivo inactivo eliminado: %s", ip)
		}
	}
}

// calculateRiskLevel calcula una puntuación de riesgo para un dispositivo.
func calculateRiskLevel(device Device) int {
	risk := 0
	if device.Vulnerable {
		risk += 8
	}
	for _, port := range device.OpenPorts {
		switch port.Port {
		case 22, 23, 3389:
			risk += 3 // Puertos de gestión remota
		case 135, 139, 445:
			risk += 5 // Puertos SMB/NetBIOS
		case 21, 25:
			risk += 2 // Servicios a menudo inseguros (FTP, SMTP)
		}
	}
	switch device.DeviceType {
	case "Router", "Firewall", "Server":
		risk += 4
	case "IoT", "Cámara IP":
		risk += 6 // A menudo son inseguros
	}
	if risk > 10 {
		return 10
	}
	return risk
}

// checkSecurityAlerts verifica si algún dispositivo supera el umbral de riesgo.
func checkSecurityAlerts() {
	var highRiskDevices []Device
	for _, device := range activeDevices {
		if device.RiskLevel >= scanConfig.AlertThreshold {
			highRiskDevices = append(highRiskDevices, device)
		}
	}
	if len(highRiskDevices) > 0 {
		showAlertNotification(highRiskDevices)
	}
}

// scanNetwork coordina el escaneo de un rango de red CIDR.
func scanNetwork(network string) []Device {
	ip, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		appLogger.Printf("Error al parsear CIDR: %v", err)
		return nil
	}

	var wg sync.WaitGroup
	results := make(chan Device, 256)
	ips := make(chan string, 256)

	for i := 0; i < scanConfig.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ips {
				if device := scanDevice(ip); device.Responsive {
					results <- device
				}
			}
		}()
	}

	go func() {
		localIP := getLocalIP()
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ipStr := ip.String()
			// Evitar escanear la IP local y la dirección de red/broadcast
			if ipStr == localIP || strings.HasSuffix(ipStr, ".0") || strings.HasSuffix(ipStr, ".255") {
				continue
			}
			ips <- ipStr
		}
		close(ips)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var devices []Device
	for device := range results {
		devices = append(devices, device)
		if len(devices) >= scanConfig.MaxDevices {
			break
		}
	}
	return devices
}

// scanDevice realiza un escaneo detallado de una única dirección IP.
func scanDevice(ip string) Device {
	device := Device{IP: ip, LastSeen: time.Now()}

	if !pingHost(ip) {
		return device
	}
	device.Responsive = true

	if mac, found := arpCache[ip]; found {
		device.MAC = mac
		device.Vendor = getVendorFromMAC(mac)
	}

	names, _ := net.LookupAddr(ip)
	if len(names) > 0 {
		device.Hostname = strings.TrimSuffix(names[0], ".")
	}

	portsToScan := scanConfig.PortProfiles[scanConfig.ActiveProfile]
	if scanConfig.FastMode {
		portsToScan = scanConfig.PortProfiles["quick"]
	}
	device.OpenPorts = portScan(ip, portsToScan)

	device.DeviceType = detectDeviceType(device)

	if scanConfig.DeepScan && len(device.OpenPorts) > 0 {
		device.Services = identifyServices(ip, device.OpenPorts)
	}

	if scanConfig.VulnScan {
		device.Vulnerable = detectVulnerabilities(device)
	}

	return device
}

// ===================================================================================
//
//                                  MÓDULO DE DETECCIÓN Y FINGERPRINTING
//
// ===================================================================================

// detectDeviceType intenta clasificar un dispositivo basado en sus características.
func detectDeviceType(device Device) string {
	// Detección por fabricante (Vendor/OUI)
	vendor := strings.ToLower(device.Vendor)
	switch {
	case strings.Contains(vendor, "raspberry"):
		return "IoT"
	case strings.Contains(vendor, "cisco"), strings.Contains(vendor, "ubiquiti"), strings.Contains(vendor, "netgear"):
		return "Router"
	case strings.Contains(vendor, "hewlett packard"), strings.Contains(vendor, "epson"), strings.Contains(vendor, "brother"):
		return "Impresora"
	case strings.Contains(vendor, "apple"):
		return "Apple Device"
	case strings.Contains(vendor, "samsung"), strings.Contains(vendor, "google"):
		return "Mobile Device"
	}

	// Detección por nombre de host (Hostname)
	host := strings.ToLower(device.Hostname)
	switch {
	case strings.Contains(host, "router"), strings.Contains(host, "gateway"):
		return "Router"
	case strings.Contains(host, "switch"):
		return "Switch"
	case strings.Contains(host, "firewall"), strings.Contains(host, "fw"):
		return "Firewall"
	case strings.Contains(host, "server"), strings.Contains(host, "srv"):
		return "Server"
	case strings.Contains(host, "nas"), strings.Contains(host, "storage"):
		return "NAS"
	case strings.Contains(host, "camera"), strings.Contains(host, "cam"):
		return "Cámara IP"
	case strings.Contains(host, "printer"), strings.Contains(host, "prn"):
		return "Impresora"
	}

	// Detección por puertos abiertos
	portMap := make(map[int]bool)
	for _, p := range device.OpenPorts {
		portMap[p.Port] = true
	}
	if (portMap[80] || portMap[443]) && (portMap[53] || portMap[67]) {
		return "Router"
	}
	if portMap[9100] || portMap[631] || portMap[515] {
		return "Impresora"
	}
	if portMap[3389] && portMap[445] {
		return "Windows PC"
	}
	if (portMap[80] || portMap[443]) && portMap[22] {
		return "Linux Server"
	}

	return "Desconocido"
}

// getVendorFromMAC busca el fabricante a partir de la dirección MAC.
func getVendorFromMAC(mac string) string {
	mac = strings.ReplaceAll(strings.ToUpper(mac), ":", "")
	if len(mac) < 6 {
		return "Desconocido"
	}
	oui := mac[0:6]
	if vendor, ok := ouiDatabase[oui]; ok {
		return vendor
	}
	return "Desconocido"
}

// pingHost comprueba si un host está activo en la red.
func pingHost(ip string) bool {
	var cmd *exec.Cmd
	timeout, _ := time.ParseDuration(scanConfig.Timeout)
	timeoutMs := fmt.Sprintf("%d", timeout.Milliseconds())

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", timeoutMs, ip)
	default: // linux, darwin
		timeoutSec := fmt.Sprintf("%.1f", timeout.Seconds())
		cmd = exec.Command("ping", "-c", "1", "-W", timeoutSec, ip)
	}
	return cmd.Run() == nil
}

// portScan escanea una lista de puertos en una IP.
func portScan(ip string, ports []int) []PortInfo {
	results := make(chan PortInfo, len(ports))
	var wg sync.WaitGroup
	sem := make(chan struct{}, scanConfig.Threads)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if isPortOpen(ip, p, "tcp") {
				results <- PortInfo{
					Port:     p,
					Protocol: "tcp",
					State:    "open",
					Service:  getServiceName(p),
				}
			}
		}(port)
	}

	wg.Wait()
	close(results)

	var openPorts []PortInfo
	for port := range results {
		openPorts = append(openPorts, port)
	}
	return openPorts
}

// isPortOpen verifica si un puerto TCP está abierto.
func isPortOpen(ip string, port int, protocol string) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	timeout, _ := time.ParseDuration(scanConfig.Timeout)
	conn, err := net.DialTimeout(protocol, target, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// getServiceName devuelve el nombre común de un servicio por su puerto.
func getServiceName(port int) string {
	// Mapeo extendido de puertos a servicios.
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
		110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
		445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
		1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
		5985: "WinRM", 5986: "WinRM-SSL", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
		8443: "HTTPS-Alt", 9100: "JetDirect",
	}
	if service, ok := services[port]; ok {
		return service
	}
	return "Desconocido"
}

// identifyServices intenta obtener el banner y la versión de los servicios.
func identifyServices(ip string, ports []PortInfo) []ServiceInfo {
	serviceChan := make(chan ServiceInfo, len(ports))
	var wg sync.WaitGroup

	for _, portInfo := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			service := ServiceInfo{Port: port, Name: getServiceName(port)}
			target := fmt.Sprintf("%s:%d", ip, port)
			timeout, _ := time.ParseDuration(scanConfig.Timeout)
			conn, err := net.DialTimeout("tcp", target, timeout)
			if err != nil {
				serviceChan <- service
				return
			}
			defer conn.Close()

			conn.SetReadDeadline(time.Now().Add(timeout))
			banner := make([]byte, 1024)
			n, _ := conn.Read(banner)
			if n > 0 {
				cleanBanner := strings.TrimSpace(string(bytes.Trim(banner[:n], "\x00")))
				service.Banner = cleanBanner
				service.Version = extractVersion(cleanBanner)
			}
			serviceChan <- service
		}(portInfo.Port)
	}

	wg.Wait()
	close(serviceChan)

	var services []ServiceInfo
	for s := range serviceChan {
		services = append(services, s)
	}
	return services
}

// extractVersion extrae información de versión de un banner de servicio.
func extractVersion(banner string) string {
	lines := strings.Split(banner, "\n")
	if len(lines) > 0 {
		// Limpiar caracteres no imprimibles
		return strings.TrimFunc(lines[0], func(r rune) bool {
			return !strconv.IsPrint(r)
		})
	}
	return ""
}

// detectVulnerabilities comprueba si un dispositivo es vulnerable.
func detectVulnerabilities(device Device) bool {
	if device.DeviceType == "IoT" && len(device.OpenPorts) > 0 {
		return true // Asumir vulnerabilidad por defecto en dispositivos IoT
	}
	for _, service := range device.Services {
		for _, vuln := range vulnerabilities {
			for _, affected := range vuln.Affected {
				if strings.Contains(strings.ToLower(service.Version), strings.ToLower(affected)) {
					appLogger.Printf("Vulnerabilidad potencial encontrada en %s: %s (%s)", device.IP, vuln.CVE, vuln.Description)
					return true
				}
			}
		}
	}
	return false
}

// ===================================================================================
//
//                                  MÓDULO DE REPORTES Y EXPORTACIÓN
//
// ===================================================================================

// saveAllResults guarda los resultados en todos los formatos configurados.
func saveAllResults() {
	deviceMutex.RLock()
	var devices []Device
	for _, device := range activeDevices {
		devices = append(devices, device)
	}
	deviceMutex.RUnlock()

	if len(devices) == 0 {
		return
	}

	// Ordenar dispositivos por IP para consistencia en los reportes.
	sort.Slice(devices, func(i, j int) bool {
		return ipToUint32(devices[i].IP) < ipToUint32(devices[j].IP)
	})

	result := ScanResult{
		Timestamp: time.Now(),
		Devices:   devices,
		Network:   scanConfig.NetworkRange,
		ScanTime:  time.Since(devices[0].LastSeen).Round(time.Second).String(),
	}

	if err := saveAsJSON(result); err != nil {
		appLogger.Printf("Error al guardar en JSON: %v", err)
	}
	if err := saveAsCSV(result); err != nil {
		appLogger.Printf("Error al guardar en CSV: %v", err)
	}
	if err := saveAsHTML(result); err != nil {
		appLogger.Printf("Error al guardar en HTML: %v", err)
	}
	if err := saveAsDOT(result); err != nil {
		appLogger.Printf("Error al guardar en DOT: %v", err)
	}
}

// saveAsJSON guarda los resultados en formato JSON.
func saveAsJSON(result ScanResult) error {
	file, err := os.Create(scanConfig.OutputFileJSON)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// saveAsCSV guarda los resultados en formato CSV.
func saveAsCSV(result ScanResult) error {
	file, err := os.Create(scanConfig.OutputFileCSV)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"IP", "MAC", "Vendor", "Hostname", "Device Type", "Open Ports", "Vulnerable", "Risk Level", "Last Seen"}
	writer.Write(headers)

	for _, device := range result.Devices {
		var ports []string
		for _, port := range device.OpenPorts {
			ports = append(ports, strconv.Itoa(port.Port))
		}
		row := []string{
			device.IP, device.MAC, device.Vendor, device.Hostname, device.DeviceType,
			strings.Join(ports, ","), strconv.FormatBool(device.Vulnerable),
			strconv.Itoa(device.RiskLevel), device.LastSeen.Format(time.RFC3339),
		}
		writer.Write(row)
	}
	return nil
}

// saveAsHTML genera un reporte HTML de los resultados.
func saveAsHTML(result ScanResult) error {
	html := `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte de Escaneo de Red</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; }
        h1, h2 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .risk-high { color: red; font-weight: bold; }
        .risk-medium { color: orange; }
        .risk-low { color: green; }
    </style>
</head>
<body>
    <h1>Reporte de Escaneo de Red</h1>
    <p><strong>Fecha:</strong> ` + result.Timestamp.Format("2006-01-02 15:04:05") + `</p>
    <p><strong>Red Escaneada:</strong> ` + result.Network + `</p>
    <h2>Dispositivos Detectados (` + strconv.Itoa(len(result.Devices)) + `)</h2>
    <table>
        <tr>
            <th>IP</th>
            <th>MAC</th>
            <th>Fabricante</th>
            <th>Hostname</th>
            <th>Tipo</th>
            <th>Puertos Abiertos</th>
            <th>Riesgo</th>
        </tr>`

	for _, device := range result.Devices {
		riskClass := "risk-low"
		if device.RiskLevel >= scanConfig.AlertThreshold {
			riskClass = "risk-high"
		} else if device.RiskLevel >= 4 {
			riskClass = "risk-medium"
		}

		var ports []string
		for _, p := range device.OpenPorts {
			ports = append(ports, strconv.Itoa(p.Port))
		}

		html += fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td class="%s">%d/10</td>
        </tr>`, device.IP, device.MAC, device.Vendor, device.Hostname, device.DeviceType, strings.Join(ports, ", "), riskClass, device.RiskLevel)
	}

	html += `
    </table>
</body>
</html>`
	return ioutil.WriteFile(scanConfig.OutputFileHTML, []byte(html), 0644)
}

// saveAsDOT genera un archivo para visualización con Graphviz.
func saveAsDOT(result ScanResult) error {
	dot := "digraph NetworkMap {\n"
	dot += "  rankdir=TB;\n"
	dot += "  node [shape=box, style=rounded];\n"
	dot += fmt.Sprintf("  label=\"Mapa de Red para %s\";\n", result.Network)

	localIP := getLocalIP()
	dot += fmt.Sprintf("  \"%s\" [label=\"Scanner\\n%s\", shape=ellipse, color=blue];\n", localIP, localIP)

	for _, device := range result.Devices {
		label := fmt.Sprintf("%s\\n%s\\n%s", device.Hostname, device.IP, device.DeviceType)
		color := "black"
		if device.RiskLevel >= scanConfig.AlertThreshold {
			color = "red"
		} else if device.RiskLevel >= 4 {
			color = "orange"
		}
		dot += fmt.Sprintf("  \"%s\" [label=\"%s\", color=%s];\n", device.IP, label, color)
		dot += fmt.Sprintf("  \"%s\" -> \"%s\";\n", localIP, device.IP)
	}

	dot += "}"
	return ioutil.WriteFile(scanConfig.OutputFileDOT, []byte(dot), 0644)
}

// ===================================================================================
//
//                                  MÓDULO DE INTERFAZ DE USUARIO (UI)
//
// ===================================================================================

// startControlPanel inicia el bucle principal del menú interactivo.
func startControlPanel() {
	for {
		deviceMutex.RLock()
		numDevices := len(activeDevices)
		deviceMutex.RUnlock()

		clearScreen()
		fmt.Println("[=== PANEL DE CONTROL - ESCÁNER DE RED ===]")
		fmt.Printf("Dispositivos activos: %d | Red: %s\n", numDevices, scanConfig.NetworkRange)
		fmt.Println(strings.Repeat("-", 45))
		fmt.Println("1. Dashboard")
		fmt.Println("2. Mostrar Dispositivos")
		fmt.Println("3. Detalles de Dispositivo")
		fmt.Println("4. Centro de Amenazas (Vulnerabilidades)")
		fmt.Println("5. Mapa de Red (Generar .dot)")
		fmt.Println("6. Exportar Resultados (JSON, CSV, HTML)")
		fmt.Println("7. Configurar Parámetros")
		fmt.Println("8. Escanear Ahora (Manual)")
		fmt.Println("9. Salir")
		fmt.Print("\nSeleccione opción: ")

		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			showDashboard()
		case 2:
			showDevices()
		case 3:
			showDeviceDetails()
		case 4:
			showVulnerabilityReport()
		case 5:
			saveAllResults()
			fmt.Printf("Mapa de red guardado en '%s'.\nUse Graphviz para visualizar: dot -Tpng %s -o map.png\n", scanConfig.OutputFileDOT, scanConfig.OutputFileDOT)
		case 6:
			saveAllResults()
			fmt.Println("Resultados exportados a JSON, CSV y HTML.")
		case 7:
			configMenu()
		case 8:
			fmt.Println("Iniciando escaneo manual...")
			go performScanCycle()
		case 9:
			appLogger.Println("Aplicación terminada por el usuario.")
			os.Exit(0)
		default:
			fmt.Println("\nOpción inválida.")
		}
		if choice >= 1 && choice <= 8 {
			fmt.Println("\nPresione Enter para continuar...")
			fmt.Scanln()
		}
	}
}

// showDashboard muestra un resumen del estado de la red.
func showDashboard() {
	deviceMutex.RLock()
	defer deviceMutex.RUnlock()

	var totalVuln, highRiskCount int
	vendorCount := make(map[string]int)
	osCount := make(map[string]int)

	for _, dev := range activeDevices {
		if dev.Vulnerable {
			totalVuln++
		}
		if dev.RiskLevel >= scanConfig.AlertThreshold {
			highRiskCount++
		}
		vendorCount[dev.Vendor]++
		osCount[dev.OS]++
	}

	clearScreen()
	fmt.Println("[=== DASHBOARD DE LA RED ===]")
	fmt.Printf("Total de Dispositivos: %d\n", len(activeDevices))
	fmt.Printf("Dispositivos Vulnerables: %d\n", totalVuln)
	fmt.Printf("Dispositivos de Alto Riesgo (>%d): %d\n", scanConfig.AlertThreshold, highRiskCount)
	fmt.Println("\n--- Top 5 Fabricantes ---")
	printTopN(vendorCount, 5)
}

// showDevices muestra una lista tabulada de los dispositivos encontrados.
func showDevices() {
	deviceMutex.RLock()
	defer deviceMutex.RUnlock()

	clearScreen()
	fmt.Println("[=== DISPOSITIVOS DETECTADOS ===]")
	fmt.Printf("%-18s %-20s %-25s %-15s %-12s %s\n", "IP", "MAC", "Fabricante", "Hostname", "Tipo", "Riesgo")
	fmt.Println(strings.Repeat("-", 100))

	var devices []Device
	for _, device := range activeDevices {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool {
		return ipToUint32(devices[i].IP) < ipToUint32(devices[j].IP)
	})

	for _, device := range devices {
		riskColor := "\033[32m" // Verde
		if device.RiskLevel >= scanConfig.AlertThreshold {
			riskColor = "\033[31m" // Rojo
		} else if device.RiskLevel >= 4 {
			riskColor = "\033[33m" // Amarillo
		}
		fmt.Printf("%-18s %-20s %-25s %-15s %-12s %s%-5d\033[0m\n",
			device.IP, device.MAC, truncate(device.Vendor, 24),
			truncate(device.Hostname, 14), truncate(device.DeviceType, 11),
			riskColor, device.RiskLevel)
	}
}

// showDeviceDetails muestra información detallada de un dispositivo específico.
func showDeviceDetails() {
	fmt.Print("Ingrese la IP del dispositivo: ")
	var ip string
	fmt.Scanln(&ip)

	deviceMutex.RLock()
	device, exists := activeDevices[ip]
	deviceMutex.RUnlock()

	if !exists {
		fmt.Println("Dispositivo no encontrado.")
		return
	}

	clearScreen()
	fmt.Printf("[=== DETALLES DEL DISPOSITIVO %s ===]\n", device.IP)
	fmt.Println("  IP:", device.IP)
	fmt.Println("  MAC:", device.MAC)
	fmt.Println("  Fabricante:", device.Vendor)
	fmt.Println("  Hostname:", device.Hostname)
	fmt.Println("  Tipo:", device.DeviceType)
	fmt.Println("  Vulnerable:", device.Vulnerable)
	fmt.Printf("  Nivel Riesgo: \033[31m%d/10\033[0m\n", device.RiskLevel)
	fmt.Println("  Última vez:", device.LastSeen.Format("2006-01-02 15:04:05"))

	if len(device.OpenPorts) > 0 {
		fmt.Println("\n--- Puertos Abiertos ---")
		for _, port := range device.OpenPorts {
			fmt.Printf("  %-5d %-8s %s\n", port.Port, port.Protocol, port.Service)
		}
	}

	if len(device.Services) > 0 {
		fmt.Println("\n--- Servicios Detectados ---")
		for _, service := range device.Services {
			fmt.Printf("  Puerto %d: %s (Versión: %s)\n", service.Port, service.Name, truncate(service.Version, 40))
		}
	}
}

// showVulnerabilityReport muestra un informe de los dispositivos vulnerables.
func showVulnerabilityReport() {
	deviceMutex.RLock()
	defer deviceMutex.RUnlock()

	var vulnDevices []Device
	for _, device := range activeDevices {
		if device.Vulnerable {
			vulnDevices = append(vulnDevices, device)
		}
	}

	clearScreen()
	fmt.Println("[=== CENTRO DE AMENAZAS ===]")
	fmt.Printf("Total de dispositivos vulnerables: %d\n", len(vulnDevices))
	fmt.Println(strings.Repeat("-", 45))

	if len(vulnDevices) == 0 {
		fmt.Println("¡Excelente! No se encontraron dispositivos vulnerables.")
	} else {
		for i, device := range vulnDevices {
			fmt.Printf("%d. IP: %s (%s) - Tipo: %s\n", i+1, device.IP, device.Hostname, device.DeviceType)
			fmt.Printf("   Riesgo: %d/10 | Causa: ", device.RiskLevel)
			// Lógica para mostrar la causa de la vulnerabilidad
			found := false
			for _, service := range device.Services {
				for _, vuln := range vulnerabilities {
					if strings.Contains(service.Version, vuln.Affected[0]) {
						fmt.Printf("%s (%s)\n", vuln.CVE, vuln.Description)
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				fmt.Println("Configuración insegura o servicio desactualizado.")
			}
		}
	}
}

// showAlertNotification muestra una notificación de alerta en la consola.
func showAlertNotification(devices []Device) {
	clearScreen()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║              ALERTA DE SEGURIDAD                 ║")
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Printf("║ Se detectaron %-2d dispositivos de alto riesgo     ║\n", len(devices))
	fmt.Println("╠══════════════════════════════════════════════════╣")
	for i, device := range devices {
		if i >= 4 {
			fmt.Printf("║ ... y %d más                                     ║\n", len(devices)-i)
			break
		}
		fmt.Printf("║ %-15s | Riesgo: %-2d/10 | Tipo: %-15s ║\n", device.IP, device.RiskLevel, truncate(device.DeviceType, 15))
	}
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println("\nPresione Enter para ver detalles en el Panel de Control...")
	fmt.Scanln()
}

// configMenu permite al usuario modificar la configuración en tiempo de ejecución.
func configMenu() {
	// Implementación del menú de configuración...
	fmt.Println("Función de configuración no implementada en esta versión.")
}

// ===================================================================================
//
//                                  FUNCIONES UTILITARIAS
//
// ===================================================================================

// truncate acorta una cadena a una longitud máxima.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return "..."
	}
	return s[:max-3] + "..."
}

// inc incrementa una dirección IP (para iterar en un rango).
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// clearScreen limpia la pantalla de la consola.
func clearScreen() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd = exec.Command("clear")
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default:
		return
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

// generatePortRange crea un slice de enteros para un rango de puertos.
func generatePortRange(start, end int) []int {
	var ports []int
	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}
	return ports
}

// ipToUint32 convierte una IP a un entero para facilitar la ordenación.
func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// printTopN imprime los N elementos más frecuentes de un mapa.
func printTopN(counts map[string]int, n int) {
	type kv struct {
		Key   string
		Value int
	}
	var ss []kv
	for k, v := range counts {
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})
	for i := 0; i < n && i < len(ss); i++ {
		fmt.Printf("  - %s: %d\n", ss[i].Key, ss[i].Value)
	}
}
