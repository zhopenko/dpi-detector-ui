package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

type TestEndpoints struct {
	DoH []string `json:"doh"`
	DoT []string `json:"dot"`
	UDP []string `json:"udp"`
}

type DNSServer struct {
	Provider string       `json:"provider"`
	DoH      string       `json:"doh"`
	DoT      string       `json:"dot"`
	UDP      string       `json:"udp"`
	RealUDP  string       `json:"real_udp"`
	Spoofing string       `json:"spoofing"`
	IP       string       `json:"ip"`
	Endpoints TestEndpoints `json:"endpoints"`
	InNDMS   bool         `json:"in_ndms"`
}

type TestResult struct {
	Timestamp string      `json:"timestamp"`
	Summary   map[string]string `json:"summary"`
	Servers   []DNSServer `json:"servers"`
	RawOutput string      `json:"raw_output"`
}

type TestStatus struct {
	Status string      `json:"status"` // "running" or "done"
	Result *TestResult `json:"result,omitempty"`
}

type DNSAction struct {
	IP       string `json:"ip"`
	Provider string `json:"provider"`
	Type     string `json:"type"` // "doh", "dot", "udp"
	Endpoint string `json:"endpoint"`
}

var (
	currentTest     *TestResult
	testMutex       sync.Mutex
	testRunning     bool
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, indexHTML)
	})

	http.HandleFunc("/api/test/start", handleTestStart)
	http.HandleFunc("/api/test/status", handleTestStatus)
	http.HandleFunc("/api/dns/add", handleDNSAdd)
	http.HandleFunc("/api/dns/remove", handleDNSRemove)
	http.HandleFunc("/api/dns/list", handleDNSList)

	log.Println("Server started on http://0.0.0.0:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleTestStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	testMutex.Lock()
	if testRunning {
		testMutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "already_running"})
		return
	}
	testRunning = true
	testMutex.Unlock()

	go runTest()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func runTest() {
	defer func() {
		testMutex.Lock()
		testRunning = false
		testMutex.Unlock()
	}()

	log.Println("Executing DNS test...")
	cmd := exec.Command("/opt/bin/dpi-detector", "-t", "1", "--ascii")
	cmd.Dir = "/opt/dpi-web"
	
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		log.Printf("Command error: %v", err)
	}

	result := parseOutput(string(output))
	
	testMutex.Lock()
	currentTest = &result
	testMutex.Unlock()
	
	log.Println("Test completed")
}

func handleTestStatus(w http.ResponseWriter, r *http.Request) {
	testMutex.Lock()
	defer testMutex.Unlock()

	status := TestStatus{}
	if testRunning {
		status.Status = "running"
	} else if currentTest != nil {
		status.Status = "done"
		status.Result = currentTest
	} else {
		status.Status = "idle"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func parseOutput(output string) TestResult {
	result := TestResult{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Summary:   make(map[string]string),
		RawOutput: output,
	}

	// Парсим Summary
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if strings.Contains(line, "DNS availability") {
			parts := strings.Split(line, "DNS availability")
			if len(parts) > 1 {
				result.Summary["Доступность DNS"] = strings.TrimSpace(strings.Trim(parts[1], "─│ "))
			}
		}
		if strings.Contains(line, "Resolver hijack") {
			parts := strings.Split(line, "Resolver hijack")
			if len(parts) > 1 {
				result.Summary["Перехват резолвера"] = strings.TrimSpace(strings.Trim(parts[1], "─│ "))
			}
		}
		if strings.Contains(line, "Answer hijack") {
			parts := strings.Split(line, "Answer hijack")
			if len(parts) > 1 {
				result.Summary["Перехват ответов"] = strings.TrimSpace(strings.Trim(parts[1], "─│ "))
			}
		}
		_ = i
	}

	// Парсим таблицы endpoints (DoH, DoT, UDP)
	endpoints := make(map[string]*TestEndpoints)
	parseEndpointsTable(output, "DoH endpoints", "DoH", endpoints)
	parseEndpointsTable(output, "DoT endpoints", "DoT", endpoints)
	parseEndpointsTable(output, "UDP endpoints", "UDP", endpoints)

	// Парсим основную таблицу результатов
	inTable := false
	for _, line := range lines {
		if strings.Contains(line, "Provider") && strings.Contains(line, "DoH") && strings.Contains(line, "Spoofing") {
			inTable = true
			continue
		}
		if inTable && strings.HasPrefix(line, "└") {
			break
		}
		if inTable && strings.HasPrefix(line, "│") && !strings.Contains(line, "╞") {
			parts := strings.Split(line, "│")
			if len(parts) >= 7 {
				provider := strings.TrimSpace(parts[1])
				if provider != "" && provider != "Provider" {
					server := DNSServer{
						Provider: provider,
						DoH:      strings.TrimSpace(parts[2]),
						DoT:      strings.TrimSpace(parts[3]),
						UDP:      strings.TrimSpace(parts[4]),
						RealUDP:  strings.TrimSpace(parts[5]),
						Spoofing: strings.TrimSpace(parts[6]),
					}
					
					// Извлекаем IP из Real UDP resolver
					ipRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
					if matches := ipRegex.FindStringSubmatch(server.RealUDP); len(matches) > 1 {
						server.IP = matches[1]
					}
					
					// Добавляем endpoints для этого провайдера
					if ep, ok := endpoints[provider]; ok {
						server.Endpoints = *ep
					}
					
					result.Servers = append(result.Servers, server)
				}
			}
		}
	}

	return result
}

func parseEndpointsTable(output, tableTitle, endpointType string, endpoints map[string]*TestEndpoints) {
	lines := strings.Split(output, "\n")
	inTable := false
	
	for _, line := range lines {
		if strings.Contains(line, tableTitle) {
			inTable = true
			continue
		}
		if inTable && strings.HasPrefix(line, "└") {
			break
		}
		if inTable && strings.HasPrefix(line, "│") && !strings.Contains(line, "╞") {
			parts := strings.Split(line, "│")
			if len(parts) >= 3 {
				provider := strings.TrimSpace(parts[1])
				endpoint := strings.TrimSpace(parts[2])
				
				if provider != "" && provider != "Provider" && endpoint != "" {
					if _, ok := endpoints[provider]; !ok {
						endpoints[provider] = &TestEndpoints{}
					}
					
					switch endpointType {
					case "DoH":
						endpoints[provider].DoH = append(endpoints[provider].DoH, endpoint)
					case "DoT":
						endpoints[provider].DoT = append(endpoints[provider].DoT, endpoint)
					case "UDP":
						endpoints[provider].UDP = append(endpoints[provider].UDP, endpoint)
					}
				}
			}
		}
	}
}

func handleDNSAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var action DNSAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var cmd *exec.Cmd
	switch action.Type {
	case "doh":
		cmd = exec.Command("/opt/bin/ndmc", "-c", fmt.Sprintf("ip name-server %s", action.Endpoint), "-c", "system configuration save")
	case "dot":
		cmd = exec.Command("/opt/bin/ndmc", "-c", fmt.Sprintf("ip name-server %s", action.Endpoint), "-c", "system configuration save")
	case "udp":
		cmd = exec.Command("/opt/bin/ndmc", "-c", fmt.Sprintf("ip name-server %s", action.IP), "-c", "system configuration save")
	default:
		http.Error(w, "Invalid type", http.StatusBadRequest)
		return
	}

	output, err := cmd.CombinedOutput()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": err == nil,
		"output":  string(output),
	})
}

func handleDNSRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var action DNSAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("/opt/bin/ndmc", "-c", fmt.Sprintf("no ip name-server %s", action.IP), "-c", "system configuration save")
	output, err := cmd.CombinedOutput()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": err == nil,
		"output":  string(output),
	})
}

func handleDNSList(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("/opt/bin/ndmc", "-c", "show ip name-server")
	output, err := cmd.Output()

	var servers []string
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "name-server") {
				parts := strings.Fields(line)
				for _, p := range parts {
					if strings.Contains(p, ".") && !strings.Contains(p, ":") {
						servers = append(servers, p)
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"servers": servers,
	})
}

const indexHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <title>DPI Detector - DNS Tests</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            padding: 15px;
            line-height: 1.5;
        }
        .container { max-width: 100%; margin: 0 auto; }
        h1 { color: #4a9eff; margin-bottom: 20px; text-align: center; font-size: 22px; }
        h2 { color: #4a9eff; margin: 20px 0 12px; font-size: 18px; }
        .btn {
            display: inline-block;
            padding: 10px 16px;
            margin: 5px;
            font-size: 14px;
            font-weight: 600;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            -webkit-tap-highlight-color: transparent;
        }
        .btn-block { display: block; width: 100%; padding: 16px; margin: 10px 0; font-size: 16px; }
        .btn-primary { background: #4a9eff; color: white; }
        .btn-success { background: #4caf50; color: white; }
        .btn-danger { background: #f44336; color: white; }
        .btn-warning { background: #ff9800; color: white; }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        
        .summary-box {
            background: #2a2a2a;
            border-radius: 10px;
            padding: 15px;
            margin: 15px 0;
            border-left: 4px solid #4a9eff;
        }
        .summary-item { margin: 8px 0; font-size: 14px; }
        .summary-label { color: #888; display: inline-block; min-width: 160px; }
        .summary-value { color: #4a9eff; font-weight: 600; }
        
        .table-container {
            overflow-x: auto;
            margin: 15px 0;
            border-radius: 10px;
            background: #2a2a2a;
        }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th {
            background: #3a3a3a;
            padding: 10px 8px;
            text-align: left;
            font-weight: 600;
            color: #4a9eff;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        td { padding: 8px; border-top: 1px solid #3a3a3a; word-break: break-word; }
        tr:hover { background: #333; }
        
        .status-ok { color: #4caf50; font-weight: 600; }
        .status-timeout { color: #ff9800; }
        .status-error { color: #f44336; }
        
        .action-btns { display: flex; gap: 5px; flex-wrap: wrap; }
        .action-btns .btn { padding: 6px 10px; font-size: 12px; margin: 2px; }
        
        .loading { text-align: center; padding: 20px; color: #888; }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.8);
        }
        .modal-content {
            background: #2a2a2a;
            margin: 10% auto;
            padding: 20px;
            border-radius: 12px;
            width: 90%;
            max-width: 500px;
            max-height: 80vh;
            overflow-y: auto;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .modal-title { color: #4a9eff; font-size: 18px; font-weight: 600; }
        .close { color: #888; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: #fff; }
        
        .endpoint-item {
            background: #1a1a1a;
            padding: 12px;
            margin: 8px 0;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
        }
        .endpoint-text { 
            font-family: monospace; 
            font-size: 13px; 
            word-break: break-all;
            flex: 1;
        }
        
        .raw-toggle { margin: 15px 0; }
        .raw-toggle summary {
            cursor: pointer;
            padding: 10px;
            background: #2a2a2a;
            border-radius: 8px;
            color: #4a9eff;
            font-weight: 600;
        }
        .raw-box {
            background: #1a1a1a;
            border-radius: 8px;
            padding: 12px;
            margin-top: 10px;
            max-height: 400px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
        }
        
        @media (max-width: 600px) {
            table { font-size: 11px; }
            th, td { padding: 6px 4px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 DPI Detector - DNS Tests</h1>
        
        <button class="btn btn-primary btn-block" id="testBtn" onclick="startTest()">
            Запустить тест DNS
        </button>
        
        <div id="testResult" style="display: none;">
            <h2>📊 Общая информация</h2>
            <div class="summary-box" id="summaryBox"></div>
            
            <h2>📋 Результаты по DNS серверам</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Провайдер</th>
                            <th>DoH</th>
                            <th>DoT</th>
                            <th>UDP</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody id="resultsBody"></tbody>
                </table>
            </div>
            
            <details class="raw-toggle">
                <summary>Показать сырой вывод</summary>
                <div class="raw-box" id="rawOutput"></div>
            </details>
        </div>
    </div>

    <div id="addModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title" id="modalTitle">Добавить DNS</div>
                <span class="close" onclick="closeModal()">&times;</span>
            </div>
            <div id="modalBody"></div>
        </div>
    </div>

    <script>
        let currentServers = [];
        let ndmsServers = [];

        function formatStatus(value) {
            if (!value || value === '-') return '<span style="color: #666;">-</span>';
            if (value.includes('TIMEOUT') || value.includes('SYN DROP') || value.includes('TLS DROP')) 
                return '<span class="status-timeout">' + value + '</span>';
            if (value.includes('BLOCKED') || value.includes('RST') || value.includes('UNKNOWN')) 
                return '<span class="status-error">' + value + '</span>';
            if (value.match(/^\d+\.?\d*ms$/)) 
                return '<span class="status-ok">' + value + '</span>';
            return value;
        }

        async function startTest() {
            const btn = document.getElementById('testBtn');
            btn.disabled = true;
            btn.textContent = 'Запуск теста...';
            
            try {
                await fetch('/api/test/start', { method: 'POST' });
                pollTestStatus();
            } catch (error) {
                alert('Ошибка запуска: ' + error.message);
                btn.disabled = false;
                btn.textContent = 'Запустить тест DNS';
            }
        }

        async function pollTestStatus() {
            const btn = document.getElementById('testBtn');
            
            const poll = async () => {
                try {
                    const response = await fetch('/api/test/status');
                    const data = await response.json();
                    
                    if (data.status === 'running') {
                        btn.textContent = 'Выполняется тест...';
                        setTimeout(poll, 2000);
                    } else if (data.status === 'done' && data.result) {
                        displayResults(data.result);
                        btn.disabled = false;
                        btn.textContent = 'Запустить тест DNS';
                    } else {
                        btn.disabled = false;
                        btn.textContent = 'Запустить тест DNS';
                    }
                } catch (error) {
                    setTimeout(poll, 2000);
                }
            };
            
            poll();
        }

        async function displayResults(data) {
            currentServers = data.servers || [];
            
            // Загружаем список DNS из NDMS
            try {
                const response = await fetch('/api/dns/list');
                const dnsData = await response.json();
                ndmsServers = dnsData.servers || [];
            } catch (error) {
                ndmsServers = [];
            }
            
            // Помечаем серверы, которые уже в NDMS
            currentServers.forEach(server => {
                server.in_ndms = ndmsServers.includes(server.ip);
            });
            
            // Отображаем сводку
            const summaryBox = document.getElementById('summaryBox');
            let summaryHTML = '';
            if (data.summary) {
                for (const [key, value] of Object.entries(data.summary)) {
                    summaryHTML += '<div class="summary-item"><span class="summary-label">' + key + ':</span> <span class="summary-value">' + value + '</span></div>';
                }
            }
            summaryBox.innerHTML = summaryHTML || '<div class="loading">Сводка недоступна</div>';
            
            // Отображаем таблицу
            const resultsBody = document.getElementById('resultsBody');
            let tableHTML = '';
            
            for (const server of currentServers) {
                tableHTML += '<tr>';
                tableHTML += '<td>' + server.provider + '</td>';
                tableHTML += '<td>' + formatStatus(server.doh) + '</td>';
                tableHTML += '<td>' + formatStatus(server.dot) + '</td>';
                tableHTML += '<td>' + formatStatus(server.udp) + '</td>';
                tableHTML += '<td><div class="action-btns">';
                
                if (server.in_ndms) {
                    tableHTML += '<button class="btn btn-danger" onclick="removeDNS(\'' + server.ip + '\', \'' + server.provider + '\')">Удалить</button>';
                    tableHTML += '<button class="btn btn-warning" onclick="showChangeModal(\'' + server.provider + '\')">Изменить</button>';
                } else {
                    tableHTML += '<button class="btn btn-success" onclick="showAddModal(\'' + server.provider + '\')">Добавить</button>';
                }
                
                tableHTML += '</div></td>';
                tableHTML += '</tr>';
            }
            
            resultsBody.innerHTML = tableHTML || '<tr><td colspan="5" class="loading">Нет данных</td></tr>';
            
            document.getElementById('rawOutput').textContent = data.raw_output || 'Вывод пуст';
            document.getElementById('testResult').style.display = 'block';
        }

        function showAddModal(provider) {
            const server = currentServers.find(s => s.provider === provider);
            if (!server) return;
            
            document.getElementById('modalTitle').textContent = 'Добавить ' + provider;
            const modalBody = document.getElementById('modalBody');
            
            let html = '<h3 style="color: #4a9eff; margin: 15px 0 10px;">Выберите тип DNS:</h3>';
            
            if (server.endpoints.doh && server.endpoints.doh.length > 0) {
                html += '<h4 style="margin: 10px 0 5px;">DoH (DNS over HTTPS):</h4>';
                server.endpoints.doh.forEach(endpoint => {
                    html += '<div class="endpoint-item">';
                    html += '<span class="endpoint-text">' + endpoint + '</span>';
                    html += '<button class="btn btn-success" onclick="addDNS(\'' + provider + '\', \'doh\', \'' + endpoint + '\', \'' + (server.ip || '') + '\')">Выбрать</button>';
                    html += '</div>';
                });
            }
            
            if (server.endpoints.dot && server.endpoints.dot.length > 0) {
                html += '<h4 style="margin: 10px 0 5px;">DoT (DNS over TLS):</h4>';
                server.endpoints.dot.forEach(endpoint => {
                    html += '<div class="endpoint-item">';
                    html += '<span class="endpoint-text">' + endpoint + '</span>';
                    html += '<button class="btn btn-success" onclick="addDNS(\'' + provider + '\', \'dot\', \'' + endpoint + '\', \'' + (server.ip || '') + '\')">Выбрать</button>';
                    html += '</div>';
                });
            }
            
            if (server.endpoints.udp && server.endpoints.udp.length > 0) {
                html += '<h4 style="margin: 10px 0 5px;">UDP (обычный DNS):</h4>';
                server.endpoints.udp.forEach(endpoint => {
                    html += '<div class="endpoint-item">';
                    html += '<span class="endpoint-text">' + endpoint + '</span>';
                    html += '<button class="btn btn-success" onclick="addDNS(\'' + provider + '\', \'udp\', \'' + endpoint + '\', \'' + (server.ip || '') + '\')">Выбрать</button>';
                    html += '</div>';
                });
            }
            
            modalBody.innerHTML = html;
            document.getElementById('addModal').style.display = 'block';
        }

        function showChangeModal(provider) {
            showAddModal(provider);
            document.getElementById('modalTitle').textContent = 'Изменить ' + provider;
        }

        function closeModal() {
            document.getElementById('addModal').style.display = 'none';
        }

        async function addDNS(provider, type, endpoint, ip) {
            if (!confirm('Добавить ' + provider + ' (' + type.toUpperCase() + ')?')) return;
            
            try {
                const response = await fetch('/api/dns/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ provider, type, endpoint, ip })
                });
                const data = await response.json();
                
                if (data.success) {
                    alert('DNS сервер добавлен');
                    closeModal();
                    startTest();
                } else {
                    alert('Ошибка: ' + data.output);
                }
            } catch (error) {
                alert('Ошибка: ' + error.message);
            }
        }

        async function removeDNS(ip, provider) {
            if (!confirm('Удалить DNS сервер ' + provider + ' (' + ip + ')?')) return;
            
            try {
                const response = await fetch('/api/dns/remove', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip, provider })
                });
                const data = await response.json();
                
                if (data.success) {
                    alert('DNS сервер удален');
                    startTest();
                } else {
                    alert('Ошибка: ' + data.output);
                }
            } catch (error) {
                alert('Ошибка: ' + error.message);
            }
        }

        window.onclick = function(event) {
            const modal = document.getElementById('addModal');
            if (event.target === modal) {
                closeModal();
            }
        }
    </script>
</body>
</html>`
