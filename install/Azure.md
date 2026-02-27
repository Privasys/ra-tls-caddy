# Azure Installation

## Get an Intel TDX Confidential VM

Azure offers **DCesv5** and **DCedsv5** series VMs with Intel TDX support. You need at minimum a `Standard_DC4es_v5` (4 vCPUs, 32 GB RAM).

### Create the VM via Azure CLI

Install the [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) if you haven't already, then:

```bash
# Login
az login

# Create a resource group
az group create \
    --name rg-tdx-dev \
    --location westeurope

# Create the TDX Confidential VM
az vm create \
    --resource-group rg-tdx-dev \
    --name tdx-vm-1 \
    --size Standard_DC4es_v5 \
    --image Canonical:ubuntu-24_04-lts-cvm:cvm:latest \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --admin-username azureuser \
    --generate-ssh-keys \
    --public-ip-sku Standard \
    --nsg-rule SSH
```

> **Note:** The `--image` flag uses Ubuntu 24.04 with Confidential VM support. The `--security-type ConfidentialVM` flag enables TDX hardware isolation. The `--os-disk-security-encryption-type VMGuestStateOnly` encrypts only the VM guest state (use `DiskWithVMGuestState` to also encrypt the OS disk).

### Create via Azure Portal

Alternatively, from the [Azure Portal](https://portal.azure.com):

1. **Create a resource → Virtual Machine**
2. Under **Size**, filter by `DCesv5` and select `Standard_DC4es_v5`
3. Under **Image**, select **Ubuntu 24.04 LTS (Confidential VM)**
4. Under **Security type**, select **Confidential virtual machine**
5. Under **Confidential compute encryption**, select **VMGuestStateOnly**
6. Under **Networking**, allow SSH (22) inbound
7. Complete the wizard and create

### Connect to the VM

```bash
ssh azureuser@<vm-public-ip>
```

Or via Azure CLI:

```bash
az ssh vm --resource-group rg-tdx-dev --name tdx-vm-1
```

## Install the Quote Generation Stack

On your **TDX Confidential VM**, install the Intel DCAP libraries:

```bash
# Update
sudo apt update
sudo apt upgrade -y

# Add the Intel SGX/TDX repository
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo gpg --dearmor -o /usr/share/keyrings/intel-sgx-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
sudo apt update

# Install the Quote Library (QL) and Quote Provider Library (QPL)
sudo apt install -y libsgx-dcap-ql libsgx-dcap-default-qpl libsgx-dcap-ql-dev
```

### Configure the Quote Provider

Azure provides its own attestation infrastructure via [Microsoft Azure Attestation (MAA)](https://learn.microsoft.com/en-us/azure/attestation/). However, the QPL still needs configuring to reach a PCCS for collateral.

```bash
sudo nano /etc/sgx_default_qcnl.conf
```

**Option A — Use your own PCCS** (recommended if you run one):

```json
{
  "pccs_url": "https://<PCCS_IP>:8081/sgx/certification/v4/",
  "use_secure_cert": true,
  "pccs_api_version": "3.1",
  "retry_times": 3,
  "retry_delay": 3
}
```

**Option B — Use Azure's built-in THIM** (Trusted Hardware Identity Management):

Azure DCesv5 VMs come with the `az-dcap-client` package which provides a QPL that fetches collateral from Azure's THIM service automatically:

```bash
# Install Azure's DCAP client (provides QPL that talks to Azure THIM)
sudo apt install -y az-dcap-client
```

When `az-dcap-client` is installed, it takes priority over `libsgx-dcap-default-qpl` and the `sgx_default_qcnl.conf` file is not used.

### Verify TDX Hardware

```bash
# Check if TDX is enabled
lscpu | grep -i tdx_guest

# Check for the TDX guest device
ls -l /dev/tdx_guest
```

*If `/dev/tdx_guest` is missing, the VM was not created with TDX confidential compute.

### Generate a TD Quote

```bash
# Install the sample code and dependencies
sudo apt install -y libtdx-attest libtdx-attest-dev gcc make

# Navigate to the sample directory
cd /opt/intel/tdx-quote-generation-sample/ 2>/dev/null || cd /usr/share/doc/libtdx-attest/examples/

# Build the sample
sudo make

# Run the test
sudo ./test_tdx_attest -d 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

You should see a **"Successfully get the TD Quote"** and have a `quote.dat`.

## Install Caddy and Privasys's RA-TLS module

### Install Go (Privasys fork with RA-TLS support)

The RA-TLS module requires a [Go fork](https://github.com/Privasys/go/tree/ratls) that adds `ClientHelloInfo.RATLSChallenge` to `crypto/tls` for challenge-response attestation.

```bash
cd ~

# Install build dependencies
sudo apt install -y git build-essential wget

# Install official Go (needed to bootstrap the fork)
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
rm go1.24.0.linux-amd64.tar.gz

# Clone the Privasys Go fork (ratls branch)
git clone -b ratls https://github.com/Privasys/go.git ~/go-ratls

# Build Go from source using official Go as bootstrap
export GOROOT_BOOTSTRAP=/usr/local/go
cd ~/go-ratls/src && ./make.bash

# Set the fork as the active Go toolchain
echo 'export GOROOT=~/go-ratls' >> ~/.bashrc
echo 'export PATH=$GOROOT/bin:$HOME/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Verify
go version
```

### Install xcaddy

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

### Build Caddy with the RA-TLS module

```bash
git clone https://github.com/Privasys/ra-tls-caddy.git ~/ra-tls-caddy
cd ~/ra-tls-caddy/src

xcaddy build --with github.com/Privasys/ra-tls-caddy=.

sudo mv caddy /usr/local/bin/caddy
sudo chmod +x /usr/local/bin/caddy

# Verify
caddy version
caddy list-modules | grep ra_tls
```

You should see `tls.issuance.ra_tls` in the module list.

### Prepare the CA certificates

Create the certs directory on the VM:

```bash
sudo mkdir -p /etc/caddy/certs
```

From your **local machine**, upload the intermediate CA certificate and key:

```bash
scp intermediate-ca.dev.crt azureuser@<vm-public-ip>:/tmp/
scp intermediate-ca.dev.key azureuser@<vm-public-ip>:/tmp/
```

Then back on the **VM**:

```bash
sudo mv /tmp/intermediate-ca.dev.crt /etc/caddy/certs/
sudo mv /tmp/intermediate-ca.dev.key /etc/caddy/certs/
sudo chown root:root /etc/caddy/certs/*
sudo chmod 644 /etc/caddy/certs/intermediate-ca.dev.crt
sudo chmod 600 /etc/caddy/certs/intermediate-ca.dev.key
```

### Create the Caddyfile

```bash
sudo mkdir -p /etc/caddy
sudo nano /etc/caddy/Caddyfile
```

```caddyfile
https://<your_host>:443 {
    tls {
        issuer ra_tls {
            backend tdx
            ca_cert /etc/caddy/certs/intermediate-ca.dev.crt
            ca_key  /etc/caddy/certs/intermediate-ca.dev.key
        }
    }
    respond "Hello from an Intel TDX Confidential VM configured with Privasys!"
}
```

### Test Caddy manually

```bash
sudo caddy run --config /etc/caddy/Caddyfile
```

From your local machine:

```bash
curl -k https://<your_host>:443
# Should print: Hello from an Intel TDX Confidential VM configured with Privasys!
```

Press `Ctrl+C` to stop.

### Create the systemd service

```bash
sudo nano /etc/systemd/system/caddy-ratls.service
```

Paste:

```ini
[Unit]
Description=Caddy RA-TLS Web Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> **Note:** Caddy runs as root because it needs access to `/sys/kernel/config/tsm/report` for TDX attestation and to the CA private key.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now caddy-ratls
sudo systemctl status caddy-ratls
```

View logs:

```bash
journalctl -u caddy-ratls -f
```

### Verify the RA-TLS certificate

From your local machine:

```bash
echo | openssl s_client -connect <your_host>:443 \
  -servername <your_host> 2>/dev/null \
  | openssl x509 -noout -text
```

Look for the TDX quote extension (`1.2.840.113741.1.5.5.1.6`) in the X.509 extensions — it should contain ~8 KB of attestation evidence.

### Network Security Group

Ensure port 443 is open in the Azure NSG:

```bash
az network nsg rule create \
    --resource-group rg-tdx-dev \
    --nsg-name tdx-vm-1NSG \
    --name AllowRATLS443 \
    --priority 1000 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-ranges 443 \
    --source-address-prefixes '*'
```

Or from the Azure Portal: **VM → Networking → Add inbound port rule → Port 443, TCP, Allow**.
