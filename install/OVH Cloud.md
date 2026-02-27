# OVH Cloud Installation (Bare Metal)

## Get an Intel TDX Bare Metal Server

OVH offers dedicated servers with Intel Xeon processors that support TDX. You need a server from the **Advance** or **Scale** range equipped with a 4th Gen Intel Xeon Scalable (Sapphire Rapids) or newer CPU with TDX support.

### Order the Server

1. Go to [OVH Bare Metal Servers](https://www.ovhcloud.com/en-gb/bare-metal/).
2. Select a server with a **4th Gen Intel Xeon Scalable** (or newer) processor — look for models like `Advance-1`, `Scale-1`, or any listing that mentions Sapphire Rapids / Emerald Rapids.
3. Choose **Ubuntu 24.04 LTS** as the operating system.
4. Select your preferred datacenter (e.g. `gra` for Gravelines, `rbx` for Roubaix, `sbg` for Strasbourg).
5. Complete the order.

### Connect to your Server

```bash
ssh root@<server-ip>
```

## Enable TDX on the Host

Unlike cloud VMs, bare metal servers require you to enable TDX in the BIOS and configure the host kernel. OVH provides IPMI/KVM access for BIOS configuration.

### Verify BIOS Support

Access the BIOS via OVH's IPMI console (available in the OVH Manager under your server's dashboard) and ensure:

- **Intel TME (Total Memory Encryption)** is enabled
- **Intel TDX** is enabled
- **Intel TDX Secure Arbitration Mode (SEAM)** is enabled

> **Note:** If you don't see TDX options, your CPU generation may not support it or the BIOS needs updating. Contact OVH support.

### Update the Kernel

TDX host support requires Linux kernel **6.7+** (ideally 6.8+). Ubuntu 24.04 ships with 6.8, which should work:

```bash
uname -r
# Should show 6.8.x or later
```

If needed, install a newer kernel:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y linux-generic-hwe-24.04
sudo reboot
```

### Configure Kernel Parameters

Enable TDX in the kernel command line:

```bash
sudo nano /etc/default/grub
```

Add `tdx=1` and `kvm_intel.tdx=1` to `GRUB_CMDLINE_LINUX_DEFAULT`:

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash tdx=1 kvm_intel.tdx=1"
```

Update GRUB and reboot:

```bash
sudo update-grub
sudo reboot
```

### Verify TDX is Active

After reboot, check that TDX is enabled:

```bash
dmesg | grep -i tdx
# Should show: "TDX module initialized" or similar

cat /sys/module/kvm_intel/parameters/tdx
# Should show: Y
```

## Create a TDX Guest VM

On a bare metal host, you need to launch a TDX-protected VM using QEMU/KVM with TDX support.

### Install Virtualisation Stack

```bash
sudo apt install -y qemu-system-x86 libvirt-daemon-system libvirt-clients \
    virt-manager bridge-utils ovmf
```

### Download a TDX-compatible Guest Image

```bash
# Download the Ubuntu 24.04 cloud image
wget https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img

# Create a disk from the cloud image
qemu-img create -f qcow2 -b noble-server-cloudimg-amd64.img -F qcow2 tdx-guest.qcow2 20G
```

### Prepare Cloud-Init

Create a `cloud-init.cfg` file for the guest VM:

```bash
cat > cloud-init.cfg << 'EOF'
#cloud-config
password: changeme
chpasswd: { expire: False }
ssh_pwauth: True
EOF

cloud-localds cloud-init.iso cloud-init.cfg
```

### Launch the TDX Guest

```bash
sudo qemu-system-x86_64 \
    -accel kvm \
    -cpu host \
    -machine q35,kernel-irqchip=split,confidential-guest-support=tdx0 \
    -object tdx-guest,id=tdx0 \
    -m 4G \
    -smp 4 \
    -nographic \
    -bios /usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive file=tdx-guest.qcow2,format=qcow2,if=virtio \
    -drive file=cloud-init.iso,format=raw,if=virtio \
    -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8443-:443 \
    -device virtio-net-pci,netdev=net0
```

> **Note:** Port 8443 on the host is forwarded to port 443 in the guest. Adjust as needed.

Connect to the guest from another terminal:

```bash
ssh -p 2222 ubuntu@localhost
```

## Install the Quote Generation Stack

All subsequent commands run **inside the TDX guest VM**.

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

### Point the Client to your PCCS

```bash
sudo nano /etc/sgx_default_qcnl.conf
```

Update the JSON (replace `<PCCS_IP>` with the IP of your PCCS server):

```json
{
  "pccs_url": "https://<PCCS_IP>:8081/sgx/certification/v4/",
  "use_secure_cert": true,
  "pccs_api_version": "3.1",
  "retry_times": 3,
  "retry_delay": 3
}
```

Verify connectivity:

```bash
curl -k https://<PCCS_IP>:8081/sgx/certification/v4/rootcacrl
```

### Verify TDX Hardware in the Guest

```bash
# Check if TDX guest support is active
lscpu | grep -i tdx_guest

# Check for the TDX guest device
ls -l /dev/tdx_guest
```

*If `/dev/tdx_guest` is missing, the VM was not launched with TDX support.

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

From your **local machine**, upload the intermediate CA certificate and key. Since the guest uses port-forwarded SSH:

```bash
scp -P 2222 intermediate-ca.dev.crt ubuntu@<host-ip>:/tmp/
scp -P 2222 intermediate-ca.dev.key ubuntu@<host-ip>:/tmp/
```

Then back on the **guest VM**:

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

From your local machine (port 8443 is forwarded to the guest's 443):

```bash
curl -k https://<host-ip>:8443
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
echo | openssl s_client -connect <host-ip>:8443 \
  -servername <your_host> 2>/dev/null \
  | openssl x509 -noout -text
```

Look for the TDX quote extension (`1.2.840.113741.1.5.5.1.6`) in the X.509 extensions — it should contain ~8 KB of attestation evidence.

### Firewall

OVH bare metal servers use `iptables` or the OVH firewall (configurable from the OVH Manager). Ensure port 8443 (or whichever port your QEMU host-forwards to) is open:

```bash
# On the bare metal host
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

Or configure the OVH Network Firewall from the **OVH Manager → IP → Firewall** section.

### Production Networking (Optional)

For production, replace QEMU user-mode networking with a bridge so the guest gets its own IP and can bind port 443 directly:

```bash
# Create a bridge on the host
sudo ip link add br0 type bridge
sudo ip link set br0 up
sudo ip addr add <host-subnet-ip>/24 dev br0

# Launch QEMU with tap networking instead of user-mode
sudo qemu-system-x86_64 \
    ... \
    -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
    -device virtio-net-pci,netdev=net0
```

This allows the TDX guest to bind port 443 directly and be addressed by its own IP.
