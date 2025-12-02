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

############################
# KEY PAIR
############################
resource "aws_key_pair" "deployer" {
  key_name   = "capstone-deployer"
  public_key = var.public_key
}

############################
# VPC (10.0.0.0/16)
############################
resource "aws_vpc" "capstone_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "capstone-vpc" }
}

############################
# SUBNETS
############################
data "aws_availability_zones" "available" {}

resource "aws_subnet" "vmnet08" {
  vpc_id            = aws_vpc.capstone_vpc.id
  cidr_block        = "10.0.8.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags = { Name = "VMnet08-10.0.8.0/24" }
}

resource "aws_subnet" "vmnet02" {
  vpc_id            = aws_vpc.capstone_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = { Name = "VMnet02-10.0.2.0/24" }
}

resource "aws_subnet" "vmnet03" {
  vpc_id            = aws_vpc.capstone_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = { Name = "VMnet03-10.0.3.0/24" }
}

resource "aws_subnet" "vmnet04" {
  vpc_id            = aws_vpc.capstone_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = { Name = "VMnet04-10.0.4.0/24" }
}

resource "aws_subnet" "vmnet05" {
  vpc_id            = aws_vpc.capstone_vpc.id
  cidr_block        = "10.0.5.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = { Name = "VMnet05-10.0.5.0/24" }
}

############################
# IGW + ROUTING
############################
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.capstone_vpc.id
  tags = { Name = "capstone-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.capstone_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "capstone-public-rt" }
}

resource "aws_route_table_association" "assoc_vmnet08" {
  subnet_id      = aws_subnet.vmnet08.id
  route_table_id = aws_route_table.public.id
}

############################
# SECURITY GROUPS
############################
resource "aws_security_group" "default_allow_internal" {
  name        = "capstone-sg-internal"
  description = "Allow internal traffic"
  vpc_id      = aws_vpc.capstone_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ssh_from_any" {
  name        = "capstone-sg-ssh"
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
}

############################
# ROUTER ENIs (3 NICs)
############################
resource "aws_network_interface" "router_eni_vmnet08" {
  subnet_id       = aws_subnet.vmnet08.id
  private_ips     = ["10.0.8.10"]
  security_groups = [aws_security_group.default_allow_internal.id]
  tags = { Name = "router-eni-vmnet08" }
}

resource "aws_network_interface" "router_eni_vmnet02" {
  subnet_id       = aws_subnet.vmnet02.id
  private_ips     = ["10.0.2.10"]
  security_groups = [aws_security_group.default_allow_internal.id]
  tags = { Name = "router-eni-vmnet02" }
}

resource "aws_network_interface" "router_eni_vmnet05" {
  subnet_id       = aws_subnet.vmnet05.id
  private_ips     = ["10.0.5.10"]
  security_groups = [aws_security_group.default_allow_internal.id]
  tags = { Name = "router-eni-vmnet05" }
}

resource "aws_instance" "router" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.deployer.key_name

  network_interface {
    network_interface_id = aws_network_interface.router_eni_vmnet02.id
    device_index         = 0
  }

  network_interface {
    network_interface_id = aws_network_interface.router_eni_vmnet08.id
    device_index         = 1
  }

  network_interface {
    network_interface_id = aws_network_interface.router_eni_vmnet05.id
    device_index         = 2
  }

  user_data = <<-EOF
    #!/bin/bash
    sysctl -w net.ipv4.ip_forward=1
    apt-get update -y
    apt-get install -y iptables-persistent
  EOF

  tags = { Name = "capstone-router-ubuntu" }
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
  tags = { Name = "bastion-eni-vmnet02" }
}

resource "aws_network_interface" "bastion_eni_vmnet03" {
  subnet_id       = aws_subnet.vmnet03.id
  private_ips     = ["10.0.3.10"]
  security_groups = [aws_security_group.default_allow_internal.id]
  tags = { Name = "bastion-eni-vmnet03" }
}

resource "aws_network_interface" "bastion_eni_vmnet04" {
  subnet_id       = aws_subnet.vmnet04.id
  private_ips     = ["10.0.4.10"]
  security_groups = [aws_security_group.default_allow_internal.id]
  tags = { Name = "bastion-eni-vmnet04" }
}

resource "aws_instance" "bastion_firewall" {
  ami           = local.vns3_ami != "" ? local.vns3_ami : data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  key_name      = aws_key_pair.deployer.key_name

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
    apt-get update -y
    apt-get install -y ufw
  EOF

  tags = { Name = "capstone-bastion-firewall" }
}

############################
# KALI (Attacker)
############################
resource "aws_network_interface" "kali_eni" {
  subnet_id       = aws_subnet.vmnet08.id
  private_ips     = ["10.0.8.128"]
  security_groups = [
    aws_security_group.default_allow_internal.id,
    aws_security_group.ssh_from_any.id
  ]
  tags = { Name = "kali-eni" }
}

resource "aws_instance" "kali_attacker" {
  ami                    = local.kali_ami != "" ? local.kali_ami : data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.deployer.key_name

  network_interface {
    network_interface_id = aws_network_interface.kali_eni.id
    device_index         = 0
  }

  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y nmap netcat tcpdump python3-pip
  EOF

  tags = { Name = "capstone-kali-attacker" }
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
  vpc_security_group_ids = [
    aws_security_group.default_allow_internal.id,
    aws_security_group.ssh_from_any.id
  ]

  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y apache2
    systemctl enable apache2

    mkdir -p /var/www/html/decoy
    echo "Internal Document - Decoy" > /var/www/html/decoy/README.txt
  EOF

  tags = { Name = "capstone-classic-pc" }
}

############################
# OUTPUTS
############################
output "vpc_id" {
  value = aws_vpc.capstone_vpc.id
}

output "subnets" {
  value = {
    VMnet08 = aws_subnet.vmnet08.id
    VMnet02 = aws_subnet.vmnet02.id
    VMnet03 = aws_subnet.vmnet03.id
    VMnet04 = aws_subnet.vmnet04.id
    VMnet05 = aws_subnet.vmnet05.id
  }
}

output "instances" {
  value = {
    router           = aws_instance.router.id
    bastion_firewall = aws_instance.bastion_firewall.id
    kali_attacker    = aws_instance.kali_attacker.id
    classic_pc       = aws_instance.classic_pc.id
  }
}
