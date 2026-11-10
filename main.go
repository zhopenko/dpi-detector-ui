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
	"time"
)

type TestResult struct {
	Timestamp string              `json:"timestamp"`
	Summary   map[string]string   `json:"summary"`
	Servers   []DNSServer         `json:"servers"`
	RawOutput string              `json:"raw_output"`
}

type DNSServer struct {
	Provider string `json:"provider"`
	DoH      string `json:"doh"`
	DoT      string `json:"dot"`
	UDP      string `json:"udp"`
	RealUDP  string `json:"real_udp"`
	Spoofing string `json:"spoofing"`
}

type DNSAction struct {
	IP string `json:"ip"`
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, indexHTML)
	})

	http.HandleFunc("/api/test", handleTest)
	http.HandleFunc("/api/dns/add", handleDNSAdd)
	http.HandleFunc("/api/dns/remove", handleDNSRemove)
	http.HandleFunc("/api/dns/list", handleDNSList)

	log.Println("Server started on http://0.0.0.0:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Println("Executing DNS test...")
	cmd := exec.Command("/opt/bin/dpi-detector", "-t", "1", "--ascii")
	cmd.Dir = "/opt/dpi-web"
	
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		log.Printf("Command error: %v", err)
	}

	// Парсим вывод в структуру
	result := parseOutput(string(output))
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
	log.Println("Test completed and sent to client")
}

func parseOutput(output string) TestResult {
	result := TestResult{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Summary:   make(map[string]string),
		RawOutput: output,
	}

	// Парсим Summary
	summaryRegex := regexp.MustCompile(`Summary.*?DNS availability\s+(\S+ DoH\s+\S+ DoT\s+\S+ UDP).*?Resolver hijack\s+(.*?)\s+Answer hijack\s+(.*?)\s+─`)
	if matches := summaryRegex.FindStringSubmatch(output); len(matches) > 3 {
		result.Summary["availability"] = strings.TrimSpace(matches[1])
		result.Summary["resolver_hijack"] = strings.TrimSpace(matches[2])
		result.Summary["answer_hijack"] = strings.TrimSpace(matches[3])
	}

	// Парсим таблицу результатов DNS
	lines := strings.Split(output, "\n")
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
				server := DNSServer{
					Provider: strings.TrimSpace(parts[1]),
					DoH:      strings.TrimSpace(parts[2]),
					DoT:      strings.TrimSpace(parts[3]),
					UDP:      strings.TrimSpace(parts[4]),
					RealUDP:  strings.TrimSpace(parts[5]),
					Spoofing: strings.TrimSpace(parts[6]),
				}
				if server.Provider != "" && server.Provider != "Provider" {
					result.Servers = append(result.Servers, server)
				}
			}
		}
	}

	return result
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

	cmd := exec.Command("/opt/bin/ndmc", "-c", fmt.Sprintf("ip name-server %s", action.IP), "-c", "system configuration save")
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
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>DPI Detector - DNS Tests</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            padding: 15px;
            line-height: 1.5;
            -webkit-text-size-adjust: 100%;
        }
        .container { max-width: 100%; margin: 0 auto; }
        h1 { 
            color: #4a9eff; 
            margin-bottom: 20px; 
            text-align: center; 
            font-size: 22px;
        }
        h2 { 
            color: #4a9eff; 
            margin: 20px 0 12px; 
            font-size: 18px;
        }
        .btn {
            display: block;
            width: 100%;
            padding: 16px;
            margin: 10px 0;
            font-size: 16px;
            font-weight: 600;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.2s;
            -webkit-tap-highlight-color: transparent;
        }
        .btn-primary { background: #4a9eff; color: white; }
        .btn-primary:active { background: #2a7edf; }
        .btn-success { background: #4caf50; color: white; }
        .btn-danger { background: #f44336; color: white; }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        
        .summary-box {
            background: #2a2a2a;
            border-radius: 10px;
            padding: 15px;
            margin: 15px 0;
            border-left: 4px solid #4a9eff;
        }
        .summary-item {
            margin: 8px 0;
            font-size: 14px;
        }
        .summary-label {
            color: #888;
            display: inline-block;
            min-width: 140px;
        }
        .summary-value {
            color: #4a9eff;
            font-weight: 600;
        }
        
        .table-container {
            overflow-x: auto;
            margin: 15px 0;
            border-radius: 10px;
            background: #2a2a2a;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
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
        td {
            padding: 8px;
            border-top: 1px solid #3a3a3a;
            word-break: break-word;
        }
        tr:hover { background: #333; }
        
        .status-ok { color: #4caf50; font-weight: 600; }
        .status-timeout { color: #ff9800; }
        .status-error { color: #f44336; }
        .status-blocked { color: #f44336; font-weight: 600; }
        .status-spoofed { color: #ff9800; font-weight: 600; }
        
        .dns-list { margin: 15px 0; }
        .dns-item {
            background: #2a2a2a;
            padding: 12px;
            margin: 8px 0;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        .dns-ip { 
            font-family: monospace; 
            font-size: 15px; 
            word-break: break-all;
            flex: 1;
        }
        .dns-actions { display: flex; gap: 8px; }
        .dns-actions .btn { 
            width: auto; 
            padding: 8px 16px; 
            margin: 0; 
            font-size: 14px;
        }
        .loading { text-align: center; padding: 20px; color: #888; }
        .add-dns {
            background: #2a2a2a;
            padding: 12px;
            border-radius: 8px;
            margin: 12px 0;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .add-dns input {
            flex: 1;
            min-width: 150px;
            padding: 10px;
            font-size: 15px;
            border: 1px solid #444;
            border-radius: 8px;
            background: #1a1a1a;
            color: #e0e0e0;
        }
        .add-dns .btn { 
            width: auto; 
            padding: 10px 18px; 
            margin: 0;
        }
        
        .raw-toggle {
            margin: 15px 0;
        }
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
            word-wrap: break-word;
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
        
        <button class="btn btn-primary" id="testBtn" onclick="runTest()">
            Запустить тест DNS
        </button>
        
        <div id="testResult" style="display: none;">
            <h2>📊 Сводка</h2>
            <div class="summary-box" id="summaryBox"></div>
            
            <h2>📋 Результаты по DNS серверам</h2>
            <div class="table-container">
                <table id="resultsTable">
                    <thead>
                        <tr>
                            <th>Провайдер</th>
                            <th>DoH</th>
                            <th>DoT</th>
                            <th>UDP</th>
                            <th>Real UDP</th>
                            <th>Spoofing</th>
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

        <h2>⚙️ Управление DNS серверами</h2>
        
        <div class="add-dns">
            <input type="text" id="newDnsIp" placeholder="Например: 1.1.1.1">
            <button class="btn btn-success" onclick="addDNS()">Добавить</button>
        </div>
        
        <button class="btn btn-primary" onclick="loadDNS()">Обновить список DNS</button>
        
        <div class="dns-list" id="dnsList">
            <div class="loading">Нажмите "Обновить список DNS"</div>
        </div>
    </div>

    <script>
        function formatStatus(value) {
            if (!value || value === '-') return '<span style="color: #666;">-</span>';
            if (value.includes('TIMEOUT') || value.includes('SYN DROP') || value.includes('TLS DROP')) 
                return '<span class="status-timeout">' + value + '</span>';
            if (value.includes('BLOCKED') || value.includes('RST') || value.includes('UNKNOWN')) 
                return '<span class="status-error">' + value + '</span>';
            if (value.match(/^\d+\.?\d*ms$/)) 
                return '<span class="status-ok">' + value + '</span>';
            if (value.match(/^\d+\/\d+/)) {
                const match = value.match(/^(\d+)\/(\d+)/);
                if (match && parseInt(match[1]) > 0) 
                    return '<span class="status-spoofed">' + value + '</span>';
            }
            return value;
        }

        async function runTest() {
            const btn = document.getElementById('testBtn');
            const resultDiv = document.getElementById('testResult');
            const summaryBox = document.getElementById('summaryBox');
            const resultsBody = document.getElementById('resultsBody');
            const rawOutput = document.getElementById('rawOutput');
            
            btn.disabled = true;
            btn.textContent = 'Выполняется тест (может занять до 1 мин)...';
            resultDiv.style.display = 'none';
            
            try {
                const response = await fetch('/api/test', { 
                    method: 'POST',
                    headers: { 'Cache-Control': 'no-cache' }
                });
                if (!response.ok) {
                    throw new Error('HTTP error! status: ' + response.status);
                }
                const data = await response.json();
                
                // Отображаем сводку
                let summaryHTML = '';
                if (data.summary) {
                    for (const [key, value] of Object.entries(data.summary)) {
                        const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                        summaryHTML += '<div class="summary-item"><span class="summary-label">' + label + ':</span> <span class="summary-value">' + value + '</span></div>';
                    }
                }
                summaryBox.innerHTML = summaryHTML || '<div class="loading">Сводка недоступна</div>';
                
                // Отображаем таблицу результатов
                let tableHTML = '';
                if (data.servers && data.servers.length > 0) {
                    for (const server of data.servers) {
                        tableHTML += '<tr>';
                        tableHTML += '<td>' + (server.provider || '-') + '</td>';
                        tableHTML += '<td>' + formatStatus(server.doh) + '</td>';
                        tableHTML += '<td>' + formatStatus(server.dot) + '</td>';
                        tableHTML += '<td>' + formatStatus(server.udp) + '</td>';
                        tableHTML += '<td>' + (server.real_udp || '-') + '</td>';
                        tableHTML += '<td>' + formatStatus(server.spoofing) + '</td>';
                        tableHTML += '</tr>';
                    }
                }
                resultsBody.innerHTML = tableHTML || '<tr><td colspan="6" class="loading">Нет данных</td></tr>';
                
                // Сырой вывод
                rawOutput.textContent = data.raw_output || 'Вывод пуст';
                
                resultDiv.style.display = 'block';
            } catch (error) {
                alert('Ошибка: ' + error.message);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Запустить тест DNS';
            }
        }

        async function loadDNS() {
            const dnsList = document.getElementById('dnsList');
            dnsList.innerHTML = '<div class="loading">Загрузка...</div>';
            
            try {
                const response = await fetch('/api/dns/list');
                const data = await response.json();
                
                if (!data.servers || data.servers.length === 0) {
                    dnsList.innerHTML = '<div class="loading">DNS серверы не найдены</div>';
                    return;
                }
                
                let html = '';
                for (let i = 0; i < data.servers.length; i++) {
                    const ip = data.servers[i];
                    html += '<div class="dns-item">';
                    html += '<span class="dns-ip">' + ip + '</span>';
                    html += '<div class="dns-actions">';
                    html += '<button class="btn btn-danger" onclick="removeDNS(\'' + ip + '\')">Удалить</button>';
                    html += '</div>';
                    html += '</div>';
                }
                dnsList.innerHTML = html;
            } catch (error) {
                dnsList.innerHTML = '<div class="loading">Ошибка загрузки</div>';
            }
        }

        async function addDNS() {
            const input = document.getElementById('newDnsIp');
            const ip = input.value.trim();
            
            if (!ip) {
                alert('Введите IP адрес DNS сервера');
                return;
            }
            
            try {
                const response = await fetch('/api/dns/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip })
                });
                const data = await response.json();
                
                if (data.success) {
                    alert('DNS сервер ' + ip + ' добавлен');
                    input.value = '';
                    loadDNS();
                } else {
                    alert('Ошибка: ' + data.output);
                }
            } catch (error) {
                alert('Ошибка: ' + error.message);
            }
        }

        async function removeDNS(ip) {
            if (!confirm('Удалить DNS сервер ' + ip + '?')) return;
            
            try {
                const response = await fetch('/api/dns/remove', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip })
                });
                const data = await response.json();
                
                if (data.success) {
                    alert('DNS сервер удален');
                    loadDNS();
                } else {
                    alert('Ошибка: ' + data.output);
                }
            } catch (error) {
                alert('Ошибка: ' + error.message);
            }
        }
    </script>
</body>
</html>`
