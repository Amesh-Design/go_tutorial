# Go Backend Quickstart

## 1. Prerequisites: Installing Go
If Go is not yet installed on Windows, open PowerShell and run:
```powershell
winget install GoLang.Go
```
*After installation, restart your terminal or IDE to refresh your `PATH`.*

Verify the installation:
```bash
go version
```

---

## 2. Running the Server
Run directly without pre-compiling:
```bash
go run main.go
```

Or compile into a single stand-alone executable binary:
```bash
go build -o server.exe main.go
./server.exe
```

---

## 3. Testing the Endpoints
### Health Check
```bash
curl http://localhost:8080/api/health
```

### Create an Item (POST)
```bash
curl -X POST http://localhost:8080/api/items \
  -H "Content-Type: application/json" \
  -d "{\"title\": \"Learn Go Concurrency\"}"
```

### List Items (GET)
```bash
curl http://localhost:8080/api/items
```
