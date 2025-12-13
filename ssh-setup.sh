#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_message() {
    echo -e "${2}${1}${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_message "Bu script root olarak çalıştırılmamalıdır. Normal kullanıcı ile çalıştırın." "$RED"
    exit 1
fi

print_message "=== Ubuntu Server SSH Kurulum Scripti ===" "$BLUE"
print_message "Bu script SSH erişimini güvenli şekilde yapılandıracaktır." "$YELLOW"

# Update system
print_message "Sistem güncellemeleri yapılıyor..." "$BLUE"
sudo apt update && sudo apt upgrade -y

# Install required packages
print_message "Gerekli paketler kuruluyor..." "$BLUE"
sudo apt install -y openssh-server ufw fail2ban

# Backup original SSH config
print_message "Mevcut SSH konfigürasyonu yedekleniyor..." "$BLUE"
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

# Get current user
CURRENT_USER=$(whoami)

# Ask for SSH port
print_message "Varsayılan SSH portu: 22" "$YELLOW"
read -p "Kullanmak istediğiniz SSH portunu girin (22 için boş bırakın): " SSH_PORT
SSH_PORT=${SSH_PORT:-22}

# Ask for authentication method
print_message "\nKimlik doğrulama yöntemi seçin:" "$BLUE"
echo "1) Parola ile giriş (önerilmez, güvensiz)"
echo "2) SSH Anahtarı ile giriş (önerilir, güvenli)"
read -p "Seçiminiz (1/2): " AUTH_CHOICE

case $AUTH_CHOICE in
    1)
        # Password authentication
        print_message "Parola ile giriş seçildi." "$YELLOW"
        print_message "ÖNEMLİ: Varsayılan parolanızı değiştirmeniz gerekecek!" "$RED"
        sudo passwd $CURRENT_USER
        
        # Configure SSH for password auth
        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config
        sudo sed -i 's/PasswordAuthentication no/#PasswordAuthentication no/g' /etc/ssh/sshd_config
        AUTH_METHOD="Parola"
        ;;
    2)
        # SSH Key authentication
        print_message "SSH Anahtarı ile giriş seçildi." "$GREEN"
        
        # Ask for public key
        print_message "\nLütfen SSH public key'inizi girin:" "$BLUE"
        print_message "(Genellikle ~/.ssh/id_rsa.pub veya ~/.ssh/id_ed25519.pub dosyasında bulunur)" "$YELLOW"
        print_message "SSH key'inizi yapıştırın ve Ctrl+D tuşuna basın:" "$BLUE"
        
        # Read multi-line input for SSH key
        SSH_KEY=$(cat)
        
        # Create .ssh directory if it doesn't exist
        mkdir -p ~/.ssh
        
        # Add key to authorized_keys
        echo "$SSH_KEY" >> ~/.ssh/authorized_keys
        
        # Set proper permissions
        chmod 700 ~/.ssh
        chmod 600 ~/.ssh/authorized_keys
        
        # Configure SSH for key auth only
        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
        sudo sed -i 's/PasswordAuthentication yes/#PasswordAuthentication yes/g' /etc/ssh/sshd_config
        
        # Generate new key pair for user if they want
        read -p "Yeni SSH anahtar çifti oluşturmak istiyor musunuz? (y/N): " GENERATE_KEY
        if [[ $GENERATE_KEY =~ ^[Yy]$ ]]; then
            ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
            print_message "\nYeni SSH anahtarı oluşturuldu!" "$GREEN"
            print_message "Private key: ~/.ssh/id_ed25519" "$YELLOW"
            print_message "Public key: ~/.ssh/id_ed25519.pub" "$YELLOW"
            print_message "\nPrivate key içeriği:" "$BLUE"
            cat ~/.ssh/id_ed25519
        fi
        
        AUTH_METHOD="SSH Anahtarı"
        ;;
    *)
        print_message "Geçersiz seçim! SSH Anahtarı yöntemi kullanılacak." "$RED"
        # Default to key auth
        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
        AUTH_METHOD="SSH Anahtarı"
        ;;
esac

# Configure SSH security settings
print_message "SSH güvenlik ayarları yapılandırılıyor..." "$BLUE"

sudo tee -a /etc/ssh/sshd_config > /dev/null << EOF

# Security enhancements added by SSH setup script
Port $SSH_PORT
PermitRootLogin no
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowUsers $CURRENT_USER
EOF

# Configure UFW firewall
print_message "Güvenlik duvarı (UFW) yapılandırılıyor..." "$BLUE"
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow $SSH_PORT/tcp
sudo ufw --force enable

# Configure Fail2Ban for SSH
print_message "Fail2Ban yapılandırılıyor..." "$BLUE"
sudo tee /etc/fail2ban/jail.local > /dev/null << EOF
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

# Restart services
print_message "Servisler yeniden başlatılıyor..." "$BLUE"
sudo systemctl restart ssh
sudo systemctl enable ssh
sudo systemctl restart fail2ban
sudo systemctl enable fail2ban

# Get network information
IP_ADDRESS=$(hostname -I | awk '{print $1}')
PUBLIC_IP=$(curl -s icanhazip.com || echo "Bilinmiyor")

# Display summary
print_message "\n=== KURULUM TAMAMLANDI ===" "$GREEN"
print_message "Aşağıdaki bilgilerle SSH bağlantısı yapabilirsiniz:" "$BLUE"
echo "----------------------------------------"
print_message "Yerel IP Adresi: $IP_ADDRESS" "$YELLOW"
print_message "Genel IP Adresi: $PUBLIC_IP" "$YELLOW"
print_message "SSH Port: $SSH_PORT" "$YELLOW"
print_message "Kullanıcı Adı: $CURRENT_USER" "$YELLOW"
print_message "Kimlik Doğrulama: $AUTH_METHOD" "$YELLOW"
echo "----------------------------------------"

# Display connection command
if [ "$AUTH_METHOD" = "SSH Anahtarı" ]; then
    print_message "\nBağlantı komutu:" "$GREEN"
    echo "ssh -p $SSH_PORT $CURRENT_USER@$IP_ADDRESS"
    
    if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
        echo "veya"
        echo "ssh -p $SSH_PORT $CURRENT_USER@$PUBLIC_IP"
    fi
    
    print_message "\nPrivate key'i kaydettiğinizden emin olun!" "$RED"
else
    print_message "\nBağlantı komutu:" "$GREEN"
    echo "ssh -p $SSH_PORT $CURRENT_USER@$IP_ADDRESS"
    
    if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
        echo "veya"
        echo "ssh -p $SSH_PORT $CURRENT_USER@$PUBLIC_IP"
    fi
    
    print_message "\nParola ile giriş yapacaksınız." "$YELLOW"
fi

print_message "\nÖNEMLİ GÜVENLİK NOTLARI:" "$RED"
echo "1. Private key'inizi asla paylaşmayın!"
echo "2. Port değişikliği yaptıysanız, bağlantıda port belirtmeyi unutmayın"
echo "3. Fail2Ban başarısız girişleri otomatik olarak banlayacaktır"
echo "4. Root girişi devre dışı bırakıldı"
echo "5. Güvenlik duvarı aktif edildi"

print_message "\nAyarlar kalıcıdır ve sunucu yeniden başlatıldığında korunur." "$GREEN"
print_message "Kurulum tamamlandı!" "$GREEN"
