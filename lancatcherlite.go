package main

import (
	"fmt"
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

// Estructuras de datos
type Device struct {
	IP     string
	MAC    string
	Vendor string
	Ports  []int
}

type ScanResult struct {
	IP    string
	Ports []int
}

// Menú principal
func main() {
	for {
		clearScreen()
		fmt.Println("[=== ESCÁNER DE RED ===]")
		fmt.Println("1. Escanear dispositivos en red local")
		fmt.Println("2. Escanear puertos específicos")
		fmt.Println("3. Analizar servicios")
		fmt.Println("4. Salir")
		fmt.Print("\nSeleccione opción: ")

		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			scanNetwork()
		case 2:
			scanPortsMenu()
		case 3:
			analyzeServices()
		case 4:
			os.Exit(0)
		default:
			fmt.Println("\nOpción inválida")
			time.Sleep(1 * time.Second)
		}
	}
}

// Funciones de utilidad
func clearScreen() {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func getNetworkRange() string {
	ip := getLocalIP()
	if ip == "" {
		return ""
	}
	parts := strings.Split(ip, ".")
	return fmt.Sprintf("%s.%s.%s.1/24", parts[0], parts[1], parts[2])
}

// Escaneo de red
func scanNetwork() {
	clearScreen()
	fmt.Println("[=== ESCANEO DE DISPOSITIVOS ===]\n")
	fmt.Println("Detectando dispositivos en la red...")
	fmt.Println("----------------------------------")

	network := getNetworkRange()
	if network == "" {
		fmt.Println("Error: No se pudo determinar la red")
		return
	}

	ip, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		fmt.Println("Error de red:", err)
		return
	}

	results := make(chan Device)
	var wg sync.WaitGroup

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		if ip.String() == getLocalIP() {
			continue // Saltar la IP local
		}

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			device := pingDevice(ip)
			if device.IP != "" {
				results <- device
				fmt.Printf("Dispositivo detectado: %-15s | MAC: %s\n", device.IP, device.MAC)
			}
		}(ip.String())
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var devices []Device
	for device := range results {
		devices = append(devices, device)
	}

	fmt.Println("\n----------------------------------")
	fmt.Printf("%d dispositivos encontrados\n", len(devices))
	fmt.Println("\nPresione Enter para continuar...")
	fmt.Scanln()
}

func pingDevice(ip string) Device {
	device := Device{IP: ip}

	// Intentar obtener MAC
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if strings.Contains(addr.String(), getLocalIP()) {
				device.MAC = iface.HardwareAddr.String()
				break
			}
		}
	}

	// Detectar puertos comunes
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 8080}
	openPorts := scanPorts(ip, commonPorts, 500*time.Millisecond)
	
	if len(openPorts) > 0 {
		device.Ports = openPorts
		return device
	}

	// Si no hay puertos abiertos, verificar con ping ICMP
	if pingHost(ip) {
		return device
	}

	return Device{} // Dispositivo no responde
}

func pingHost(ip string) bool {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("ping", "-n", "1", "-w", "500", ip)
		_, err := cmd.CombinedOutput()
		return err == nil
	default:
		cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
		_, err := cmd.CombinedOutput()
		return err == nil
	}
}

// Escaneo de puertos
func scanPortsMenu() {
	clearScreen()
	fmt.Println("[=== ESCANEO DE PUERTOS ===]\n")
	fmt.Print("Ingrese dirección IP: ")
	var ip string
	fmt.Scanln(&ip)

	fmt.Print("Puertos (ej: 80 o 1-1000): ")
	var portsInput string
	fmt.Scanln(&portsInput)

	ports := parsePorts(portsInput)
	if len(ports) == 0 {
		fmt.Println("Formato de puertos inválido")
		return
	}

	fmt.Printf("\nEscaneando %d puertos en %s...\n", len(ports), ip)
	fmt.Println("----------------------------------")

	results := scanPorts(ip, ports, 2*time.Second)
	sort.Ints(results)

	for _, port := range results {
		service := getServiceName(port)
		fmt.Printf("Puerto %-5d [ABIERTO] -> %s\n", port, service)
	}

	fmt.Println("\n----------------------------------")
	fmt.Printf("%d puertos abiertos encontrados\n", len(results))
	fmt.Println("\nPresione Enter para continuar...")
	fmt.Scanln()
}

func parsePorts(input string) []int {
	if strings.Contains(input, "-") {
		parts := strings.Split(input, "-")
		start, _ := strconv.Atoi(parts[0])
		end, _ := strconv.Atoi(parts[1])
		
		var ports []int
		for port := start; port <= end; port++ {
			ports = append(ports, port)
		}
		return ports
	}
	
	port, _ := strconv.Atoi(input)
	return []int{port}
}

func scanPorts(ip string, ports []int, timeout time.Duration) []int {
	results := make(chan int)
	var wg sync.WaitGroup
	var openPorts []int

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if isPortOpen(ip, p, timeout) {
				results <- p
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for port := range results {
		fmt.Printf("Puerto %d [ABIERTO]\n", port)
		openPorts = append(openPorts, port)
	}

	return openPorts
}

func isPortOpen(ip string, port int, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Análisis de servicios
func analyzeServices() {
	clearScreen()
	fmt.Println("[=== ANÁLISIS DE SERVICIOS ===]\n")
	fmt.Print("Ingrese dirección IP: ")
	var ip string
	fmt.Scanln(&ip)

	fmt.Println("\nIdentificando servicios...")
	fmt.Println("----------------------------------")

	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080, 3306}
	for _, port := range commonPorts {
		service := identifyService(ip, port)
		if service != "" {
			fmt.Printf("Puerto %-5d -> %s\n", port, service)
		}
	}

	fmt.Println("\nAnálisis completado")
	fmt.Println("\nPresione Enter para continuar...")
	fmt.Scanln()
}

func identifyService(ip string, port int) string {
	if !isPortOpen(ip, port, 2*time.Second) {
		return ""
	}

	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 80, 8080:
		return "HTTP"
	case 443:
		return "HTTPS"
	default:
		buffer := make([]byte, 256)
		_, err := conn.Read(buffer)
		if err == nil {
			if strings.Contains(string(buffer), "SMTP") {
				return "SMTP"
			}
			if strings.Contains(string(buffer), "POP3") {
				return "POP3"
			}
			if strings.Contains(string(buffer), "IMAP") {
				return "IMAP"
			}
		}
		return getServiceName(port)
	}
}

func getServiceName(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 3306:
		return "MySQL"
	default:
		return "Desconocido"
	}
}

// Utilidades de red
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
