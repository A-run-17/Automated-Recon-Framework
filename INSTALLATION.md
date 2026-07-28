## 1. Update Ubuntu and check Python
```bash
sudo apt update && sudo apt upgrade -y
python3 --version
```
> Needs 3.11+.
> 
```bash
sudo apt install -y python3.11
```
> Then use python3.11 instead of python3 in the commands below (or sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 to make it the default). Ubuntu 24.04 ships Python 3.12 already — you're fine as-is.

## 2. Install Nmap and unzip
```bash
sudo apt install -y nmap unzip
```

## 3. Install Go

> Ubuntu's apt Go package is often outdated. Better to grab the latest directly:

```bash
cd /tmp
curl -LO https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

(Check https://go.dev/dl/ for the current release number if go1.23.4 is stale by the time you run this.)

## 4. Install the Go-based recon tools
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/sensepost/gowitness@latest
```
## 5. Install Amass

> Ubuntu's apt version is old/unavailable in some releases — install it via Go instead for a current build:

```bash
go install -v github.com/owasp-amass/amass/v4/...@master
```

## 6. Install Chromium for GoWitness
```bash
sudo apt install -y chromium-browser
```

> If that package name isn't found on your Ubuntu version, try:

```bash
sudo snap install chromium
```

## 7. Verify everything's on PATH

```bash
which subfinder httpx assetfinder gowitness amass nmap
```

> Anything missing just means that stage skips with a warning — not a crash.

## 8. Run it

No pip install needed.

```bash
cd ~/projects/Automated-Recon-Framework
python3 recon.py example.com
```

Other options:

```bash
python3 recon.py example.com --subdomains
python3 recon.py example.com --ports --http
python3 recon.py example.com --threads 30 --timeout 15
```


