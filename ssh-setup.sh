#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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

# Get server hostname
SERVER_HOSTNAME=$(hostname)

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
        
        # Generate new SSH key pair
        print_message "Yeni SSH anahtar çifti oluşturuluyor..." "$BLUE"
        KEY_NAME="id_ed25519_${SERVER_HOSTNAME}_$(date +%Y%m%d)"
        
        # Generate Ed25519 key (best practice)
        ssh-keygen -t ed25519 -f ~/.ssh/${KEY_NAME} -N "" -C "ssh-key-for-${SERVER_HOSTNAME}-$(date +%Y-%m-%d)"
        
        # Set proper permissions
        chmod 700 ~/.ssh
        chmod 600 ~/.ssh/${KEY_NAME}
        chmod 644 ~/.ssh/${KEY_NAME}.pub
        
        # Add public key to authorized_keys
        cat ~/.ssh/${KEY_NAME}.pub >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        
        # Configure SSH for key auth only
        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
        sudo sed -i 's/PasswordAuthentication yes/#PasswordAuthentication yes/g' /etc/ssh/sshd_config
        
        # Create SSH config for easier connection
        SSH_CONFIG_ENTRY="Host ${SERVER_HOSTNAME}
    HostName %h
    User ${CURRENT_USER}
    Port ${SSH_PORT}
    IdentityFile ~/.ssh/${KEY_NAME}
    IdentitiesOnly yes"
        
        print_message "\nSSH anahtar çifti başarıyla oluşturuldu!" "$GREEN"
        print_message "┌──────────────────────────────────────────────────────┐" "$PURPLE"
        print_message "│                   SSH KEY BİLGİLERİ                  │" "$PURPLE"
        print_message "└──────────────────────────────────────────────────────┘" "$PURPLE"
        print_message "Public Key Dosyası:  ~/.ssh/${KEY_NAME}.pub" "$CYAN"
        print_message "Private Key Dosyası: ~/.ssh/${KEY_NAME}" "$CYAN"
        print_message "Key Tipi:            ED25519 (en güvenli)" "$CYAN"
        
        # Display private key with clear formatting
        print_message "\n┌──────────────────────────────────────────────────────┐" "$PURPLE"
        print_message "│                  PRIVATE KEY İÇERİĞİ                 │" "$PURPLE"
        print_message "└──────────────────────────────────────────────────────┘" "$PURPLE"
        print_message "AŞAĞIDAKİ TÜM SATIRLARI KOPYALAYIN:" "$RED"
        echo ""
        cat ~/.ssh/${KEY_NAME}
        echo ""
        print_message "YUKARIDAKİ TÜM SATIRLARI KOPYALAYIN" "$RED"
        
        print_message "\n┌──────────────────────────────────────────────────────┐" "$PURPLE"
        print_message "│               KURULUM TALİMATLARI                    │" "$PURPLE"
        print_message "└──────────────────────────────────────────────────────┘" "$PURPLE"
        print_message "1. Private key'i kendi bilgisayarınıza kaydedin:" "$CYAN"
        print_message "   nano ~/.ssh/${KEY_NAME}" "$YELLOW"
        print_message "2. Dosya izinlerini ayarlayın:" "$CYAN"
        print_message "   chmod 600 ~/.ssh/${KEY_NAME}" "$YELLOW"
        print_message "3. SSH config dosyasına ekleyin (~/.ssh/config):" "$CYAN"
        print_message "   ${SSH_CONFIG_ENTRY}" "$YELLOW"
        
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
print_message "\nSSH güvenlik ayarları yapılandırılıyor..." "$BLUE"

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
PubkeyAuthentication yes
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
findtime = 600
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
print_message "\n┌──────────────────────────────────────────────────────┐" "$GREEN"
print_message "│              KURULUM TAMAMLANDI                    │" "$GREEN"
print_message "└──────────────────────────────────────────────────────┘" "$GREEN"
print_message "Aşağıdaki bilgilerle SSH bağlantısı yapabilirsiniz:" "$BLUE"
echo ""
print_message "• Sunucu Adı:      $SERVER_HOSTNAME" "$CYAN"
print_message "• Yerel IP:        $IP_ADDRESS" "$CYAN"
print_message "• Genel IP:        $PUBLIC_IP" "$CYAN"
print_message "• SSH Port:        $SSH_PORT" "$CYAN"
print_message "• Kullanıcı:       $CURRENT_USER" "$CYAN"
print_message "• Kimlik Doğrulama: $AUTH_METHOD" "$CYAN"
echo ""

# Display connection commands
if [ "$AUTH_METHOD" = "SSH Anahtarı" ]; then
    print_message "BAĞLANTI SEÇENEKLERİ:" "$GREEN"
    echo ""
    
    # Option 1: With SSH config
    print_message "1. SSH Config kullanarak (tavsiye edilen):" "$BLUE"
    print_message "   ~/.ssh/config dosyanıza ekleyin:" "$YELLOW"
    echo "   Host $SERVER_HOSTNAME"
    echo "       HostName $IP_ADDRESS"
    echo "       User $CURRENT_USER"
    if [ "$SSH_PORT" != "22" ]; then
        echo "       Port $SSH_PORT"
    fi
    echo "       IdentityFile ~/.ssh/${KEY_NAME}"
    echo "       IdentitiesOnly yes"
    echo ""
    print_message "   Sonra basitçe çalıştırın:" "$YELLOW"
    print_message "   ssh $SERVER_HOSTNAME" "$GREEN"
    echo ""
    
    # Option 2: Direct connection
    print_message "2. Direkt bağlantı:" "$BLUE"
    if [ "$SSH_PORT" = "22" ]; then
        print_message "   ssh -i ~/.ssh/${KEY_NAME} $CURRENT_USER@$IP_ADDRESS" "$GREEN"
    else
        print_message "   ssh -i ~/.ssh/${KEY_NAME} -p $SSH_PORT $CURRENT_USER@$IP_ADDRESS" "$GREEN"
    fi
    
    if [ "$PUBLIC_IP" != "Bilinmiyor" ] && [ "$PUBLIC_IP" != "$IP_ADDRESS" ]; then
        if [ "$SSH_PORT" = "22" ]; then
            print_message "   veya:" "$BLUE"
            print_message "   ssh -i ~/.ssh/${KEY_NAME} $CURRENT_USER@$PUBLIC_IP" "$GREEN"
        else
            print_message "   veya:" "$BLUE"
            print_message "   ssh -i ~/.ssh/${KEY_NAME} -p $SSH_PORT $CURRENT_USER@$PUBLIC_IP" "$GREEN"
        fi
    fi
    
    print_message "\n⚠️  PRIVATE KEY'İ GÜVENLİ BİR YERE KAYDEDİN! ⚠️" "$RED"
    print_message "Kaybettiğinizde sunucuya erişemezsiniz!" "$RED"
else
    print_message "BAĞLANTI KOMUTLARI:" "$GREEN"
    echo ""
    if [ "$SSH_PORT" = "22" ]; then
        print_message "   ssh $CURRENT_USER@$IP_ADDRESS" "$GREEN"
    else
        print_message "   ssh -p $SSH_PORT $CURRENT_USER@$IP_ADDRESS" "$GREEN"
    fi
    
    if [ "$PUBLIC_IP" != "Bilinmiyor" ] && [ "$PUBLIC_IP" != "$IP_ADDRESS" ]; then
        if [ "$SSH_PORT" = "22" ]; then
            print_message "   veya:" "$BLUE"
            print_message "   ssh $CURRENT_USER@$PUBLIC_IP" "$GREEN"
        else
            print_message "   veya:" "$BLUE"
            print_message "   ssh -p $SSH_PORT $CURRENT_USER@$PUBLIC_IP" "$GREEN"
        fi
    fi
fi

print_message "\n┌──────────────────────────────────────────────────────┐" "$PURPLE"
print_message "│                GÜVENLİK BİLGİLERİ                   │" "$PURPLE"
print_message "└──────────────────────────────────────────────────────┘" "$PURPLE"
print_message "• Fail2Ban aktif: 3 başarısız girişte 1 saat ban" "$CYAN"
print_message "• Root erişimi: DEVRE DIŞI" "$CYAN"
print_message "• Güvenlik duvarı: AKTİF (sadece port $SSH_PORT açık)" "$CYAN"
print_message "• Maksimum oturum: 5 eşzamanlı bağlantı" "$CYAN"
print_message "• Bağlantı timeout: 10 dakika aktif kalmama" "$CYAN"
print_message "\nAyarlar kalıcıdır ve sunucu yeniden başlatıldığında korunur." "$GREEN"
print_message "\nKurulum tamamlandı! 🎉" "$GREEN"
