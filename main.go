package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type TestResult struct {
	Timestamp string   `json:"timestamp"`
	Output    string   `json:"output"`
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

	fmt.Println("Server started on http://0.0.0.0:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cmd := exec.Command("/opt/bin/dpi-detector", "-t", "1", "--batch")
	output, err := cmd.CombinedOutput()

	result := TestResult{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Output:    string(output),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)

	if err != nil {
		log.Printf("Test error: %v", err)
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DPI Detector - DNS Tests</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            padding: 20px;
            line-height: 1.6;
        }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #4a9eff; margin-bottom: 30px; text-align: center; }
        h2 { color: #4a9eff; margin: 20px 0 15px; }
        .btn {
            display: block;
            width: 100%;
            padding: 18px;
            margin: 15px 0;
            font-size: 18px;
            font-weight: 600;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .btn-primary { background: #4a9eff; color: white; }
        .btn-primary:hover { background: #3a8eef; }
        .btn-success { background: #4caf50; color: white; }
        .btn-danger { background: #f44336; color: white; }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .result-box {
            background: #2a2a2a;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            max-height: 400px;
            overflow-y: auto;
            font-family: "Courier New", monospace;
            font-size: 14px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .dns-list { margin: 20px 0; }
        .dns-item {
            background: #2a2a2a;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        .dns-ip { font-family: monospace; font-size: 16px; }
        .dns-actions { display: flex; gap: 10px; }
        .dns-actions .btn { width: auto; padding: 10px 20px; margin: 0; font-size: 14px; }
        .loading { text-align: center; padding: 20px; color: #888; }
        .add-dns {
            background: #2a2a2a;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            display: flex;
            gap: 10px;
        }
        .add-dns input {
            flex: 1;
            padding: 12px;
            font-size: 16px;
            border: 1px solid #444;
            border-radius: 8px;
            background: #1a1a1a;
            color: #e0e0e0;
        }
        .add-dns .btn { width: auto; padding: 12px 20px; margin: 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 DPI Detector - DNS Tests</h1>
        
        <button class="btn btn-primary" id="testBtn" onclick="runTest()">
            Запустить тест DNS
        </button>
        
        <div id="testResult" style="display: none;">
            <h2>Результаты теста:</h2>
            <div class="result-box" id="resultBox"></div>
        </div>

        <h2>Управление DNS серверами</h2>
        
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
        async function runTest() {
            const btn = document.getElementById('testBtn');
            const resultDiv = document.getElementById('testResult');
            const resultBox = document.getElementById('resultBox');
            
            btn.disabled = true;
            btn.textContent = 'Выполняется тест...';
            resultDiv.style.display = 'none';
            
            try {
                const response = await fetch('/api/test', { method: 'POST' });
                const data = await response.json();
                
                resultBox.textContent = data.output;
                resultDiv.style.display = 'block';
            } catch (error) {
                resultBox.textContent = 'Ошибка: ' + error.message;
                resultDiv.style.display = 'block';
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
