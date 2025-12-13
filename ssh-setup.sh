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

# Get server hostname (simplified)
SERVER_HOSTNAME=$(hostname | cut -d'.' -f1 | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')

# If server hostname is empty, use a default
if [ -z "$SERVER_HOSTNAME" ]; then
    SERVER_HOSTNAME="server"
fi

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
        
        KEY_NAME="$SERVER_HOSTNAME"
        KEY_PATH="$HOME/.ssh/$KEY_NAME"
        
        # Anahtar oluştur
        ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "$CURRENT_USER@$SERVER_HOSTNAME"
        
        # Public key'i authorized_keys'e ekle
        cat "$KEY_PATH.pub" >> ~/.ssh/authorized_keys
        
        # Doğrulama bilgileri
        KEY_CHECKSUM=$(sha256sum "$KEY_PATH" | awk '{print $1}')
        KEY_BASE64=$(base64 -w 0 "$KEY_PATH")
        
        print_message "\n🔐 PRIVATE KEY BİLGİLERİ:" "$PURPLE"
        print_message "SHA256 Checksum: $KEY_CHECKSUM" "$CYAN"
        
        print_message "\n📋 BASE64 ENCODE EDİLMİŞ PRIVATE KEY:" "$BLUE"
        echo "$KEY_BASE64"
        
        print_message "\n📥 KURULUM TALİMATLARI:" "$GREEN"
        print_message "1. Yukarıdaki BASE64 kodunu kopyalayın" "$YELLOW"
        print_message "2. Yerel bilgisayarınızda şu komutu çalıştırın:" "$YELLOW"
        echo "   echo '$KEY_BASE64' | base64 -d > $KEY_NAME"
        print_message "3. Dosya izinlerini ayarlayın:" "$YELLOW"
        echo "   chmod 600 $KEY_NAME"
        print_message "4. SHA256 kontrolü yapın:" "$YELLOW"
        echo "   sha256sum $KEY_NAME"
        print_message "   Çıktı: $KEY_CHECKSUM olmalı" "$GREEN"
        
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

if [ "$AUTH_METHOD" = "SSH Anahtarı" ]; then
    print_message "• Anahtar Çifti:    $KEY_NAME ve $KEY_NAME.pub" "$CYAN"
    print_message "• Public Key Yeri:  ~/.ssh/authorized_keys" "$CYAN"
fi
echo ""

# Display connection instructions
if [ "$AUTH_METHOD" = "SSH Anahtarı" ]; then
    print_message "┌──────────────────────────────────────────────────────┐" "$PURPLE"
    print_message "│              KURULUM TALİMATLARI                    │" "$PURPLE"
    print_message "└──────────────────────────────────────────────────────┘" "$PURPLE"
    
    print_message "\n📁 ADIM 1: Private Key'i İndirin" "$BLUE"
    print_message "1. Yukarıdaki private key içeriğini kopyalayın" "$YELLOW"
    print_message "2. Yerel bilgisayarınızda '$SERVER_HOSTNAME' klasörü oluşturun:" "$YELLOW"
    print_message "   mkdir ~/'$SERVER_HOSTNAME'" "$GREEN"
    print_message "3. Bu klasöre girin:" "$YELLOW"
    print_message "   cd ~/'$SERVER_HOSTNAME'" "$GREEN"
    print_message "4. '$KEY_NAME' adlı dosya oluşturun ve private key'i yapıştırın:" "$YELLOW"
    print_message "   nano '$KEY_NAME'" "$GREEN"
    print_message "5. Dosya izinlerini ayarlayın (ÖNEMLİ!):" "$YELLOW"
    print_message "   chmod 600 '$KEY_NAME'" "$GREEN"
    
    print_message "\n🔑 ADIM 2: SSH Agent Kullanarak Bağlanın (TAVSIYE EDİLEN)" "$BLUE"
    print_message "1. '$SERVER_HOSTNAME' klasöründe terminal açın" "$YELLOW"
    print_message "2. SSH agent'ı başlatın ve anahtarı ekleyin:" "$YELLOW"
    print_message "   eval \"\$(ssh-agent -s)\"" "$GREEN"
    print_message "   ssh-add '$KEY_NAME'" "$GREEN"
    print_message "3. Artık bağlanabilirsiniz:" "$YELLOW"
    
    if [ "$SSH_PORT" = "22" ]; then
        print_message "   ssh $CURRENT_USER@$IP_ADDRESS" "$GREEN"
        if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
            print_message "   veya:" "$BLUE"
            print_message "   ssh $CURRENT_USER@$PUBLIC_IP" "$GREEN"
        fi
    else
        print_message "   ssh -p $SSH_PORT $CURRENT_USER@$IP_ADDRESS" "$GREEN"
        if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
            print_message "   veya:" "$BLUE"
            print_message "   ssh -p $SSH_PORT $CURRENT_USER@$PUBLIC_IP" "$GREEN"
        fi
    fi
    
    print_message "\n⚡ ADIM 3: Direkt -i ile Bağlanma (Alternatif)" "$BLUE"
    print_message "1. '$SERVER_HOSTNAME' klasöründe terminal açın" "$YELLOW"
    print_message "2. Doğrudan private key'i belirterek bağlanın:" "$YELLOW"
    
    if [ "$SSH_PORT" = "22" ]; then
        print_message "   ssh -i '$KEY_NAME' $CURRENT_USER@$IP_ADDRESS" "$GREEN"
        if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
            print_message "   veya:" "$BLUE"
            print_message "   ssh -i '$KEY_NAME' $CURRENT_USER@$PUBLIC_IP" "$GREEN"
        fi
    else
        print_message "   ssh -i '$KEY_NAME' -p $SSH_PORT $CURRENT_USER@$IP_ADDRESS" "$GREEN"
        if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
            print_message "   veya:" "$BLUE"
            print_message "   ssh -i '$KEY_NAME' -p $SSH_PORT $CURRENT_USER@$PUBLIC_IP" "$GREEN"
        fi
    fi
    
    print_message "\n📝 NOT: SSH config dosyası kullanmak isterseniz:" "$BLUE"
    print_message "~/.ssh/config dosyanıza şunu ekleyin:" "$YELLOW"
    echo "Host $SERVER_HOSTNAME"
    echo "    HostName $IP_ADDRESS"
    echo "    User $CURRENT_USER"
    if [ "$SSH_PORT" != "22" ]; then
        echo "    Port $SSH_PORT"
    fi
    echo "    IdentityFile ~/$(echo $SERVER_HOSTNAME | sed 's/ /\\ /g')/$KEY_NAME"
    
    print_message "\nSonra sadece şunu çalıştırın:" "$YELLOW"
    print_message "   ssh $SERVER_HOSTNAME" "$GREEN"
    
else
    print_message "\n🔑 PAROLA İLE BAĞLANTI:" "$BLUE"
    if [ "$SSH_PORT" = "22" ]; then
        print_message "   ssh $CURRENT_USER@$IP_ADDRESS" "$GREEN"
        if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
            print_message "   veya:" "$BLUE"
            print_message "   ssh $CURRENT_USER@$PUBLIC_IP" "$GREEN"
        fi
    else
        print_message "   ssh -p $SSH_PORT $CURRENT_USER@$IP_ADDRESS" "$GREEN"
        if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
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

print_message "\n✅ Ayarlar kalıcıdır ve sunucu yeniden başlatıldığında korunur." "$GREEN"
print_message "\n🎉 Kurulum tamamlandı!" "$GREEN"

# Create a setup summary file
SUMMARY_FILE="$HOME/ssh_setup_summary.txt"
cat > "$SUMMARY_FILE" << EOF
SSH Kurulum Özeti - $(date)
===============================
Sunucu Adı: $SERVER_HOSTNAME
Yerel IP: $IP_ADDRESS
Genel IP: $PUBLIC_IP
SSH Port: $SSH_PORT
Kullanıcı: $CURRENT_USER
Kimlik Doğrulama: $AUTH_METHOD

$(if [ "$AUTH_METHOD" = "SSH Anahtarı" ]; then
echo "Anahtar Bilgileri:"
echo "• Private Key: $KEY_NAME"
echo "• Public Key: $KEY_NAME.pub"
echo "• Public Key Konumu: ~/.ssh/authorized_keys"
fi)

Bağlantı Komutları:
$(if [ "$AUTH_METHOD" = "SSH Anahtarı" ]; then
    if [ "$SSH_PORT" = "22" ]; then
        echo "ssh -i '$KEY_NAME' $CURRENT_USER@$IP_ADDRESS"
    else
        echo "ssh -i '$KEY_NAME' -p $SSH_PORT $CURRENT_USER@$IP_ADDRESS"
    fi
else
    if [ "$SSH_PORT" = "22" ]; then
        echo "ssh $CURRENT_USER@$IP_ADDRESS"
    else
        echo "ssh -p $SSH_PORT $CURRENT_USER@$IP_ADDRESS"
    fi
fi)

Güvenlik Ayarları:
• Fail2Ban: 3 başarısız girişte 1 saat ban
• Root girişi: Kapalı
• Güvenlik duvarı: Aktif
EOF

print_message "\n📄 Detaylı özet dosyası: $SUMMARY_FILE" "$BLUE"
