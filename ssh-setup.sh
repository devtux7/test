#!/bin/bash

# This script sets up SSH on a fresh Ubuntu Server LTS installation.
# It installs OpenSSH server, configures the firewall, enables the service,
# and optionally sets up key-based authentication for better security.
# Best practices: Use UFW for firewall, enable on boot, suggest key auth.
# Run this as root or with sudo.

set -e  # Exit on error

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run this script as root or using sudo."
        exit 1
    fi
}

# Update system packages
update_packages() {
    echo "Updating package lists..."
    apt update -y
    apt upgrade -y
}

# Install OpenSSH server if not installed
install_ssh() {
    if ! dpkg -l | grep -q openssh-server; then
        echo "Installing OpenSSH server..."
        apt install openssh-server -y
    else
        echo "OpenSSH server is already installed."
    fi
}

# Enable and start SSH service
enable_ssh() {
    echo "Enabling and starting SSH service..."
    systemctl enable ssh
    systemctl start ssh
    systemctl status ssh --no-pager
}

# Configure firewall (UFW)
configure_firewall() {
    if ! dpkg -l | grep -q ufw; then
        echo "Installing UFW..."
        apt install ufw -y
    fi

    echo "Configuring UFW to allow SSH..."
    ufw allow OpenSSH
    ufw --force enable
    ufw status
}

# Optional: Set up key-based authentication
setup_key_auth() {
    read -p "Do you want to set up SSH key-based authentication? (y/n): " choice
    if [[ $choice =~ ^[Yy]$ ]]; then
        echo "Generating SSH key pair if not exists..."
        if [ ! -f ~/.ssh/id_rsa ]; then
            ssh-keygen -t rsa -b 4096 -C "your_email@example.com" -N "" -f ~/.ssh/id_rsa
        fi

        echo "Adding public key to authorized_keys..."
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys

        echo "Disabling password authentication for security..."
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        systemctl restart ssh

        echo "SSH key setup complete. Copy your private key (~/.ssh/id_rsa) to your client machine."
        echo "Public IP: $(curl -s ifconfig.me)"
    else
        echo "Skipping key-based authentication setup."
    fi
}

# Optional: Change SSH port for added security
change_ssh_port() {
    read -p "Do you want to change the default SSH port (22) for security? (y/n): " choice
    if [[ $choice =~ ^[Yy]$ ]]; then
        read -p "Enter new SSH port (e.g., 2222): " new_port
        sed -i "s/#Port 22/Port $new_port/" /etc/ssh/sshd_config
        sed -i "s/Port 22/Port $new_port/" /etc/ssh/sshd_config
        ufw allow $new_port/tcp
        ufw delete allow 22/tcp
        systemctl restart ssh
        echo "SSH port changed to $new_port. Update your client connections accordingly."
    else
        echo "Keeping default SSH port 22."
    fi
}

# Main execution
check_root
update_packages
install_ssh
enable_ssh
configure_firewall
change_ssh_port
setup_key_auth

echo "SSH setup complete! You can now connect via SSH from local network or internet."
echo "Server IP: $(hostname -I | awk '{print $1}')"
echo "Public IP (if applicable): $(curl -s ifconfig.me || echo 'Not detectable')"
echo "Settings will persist after reboot."
