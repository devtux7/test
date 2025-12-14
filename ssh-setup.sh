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

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_message "❌ Bu script root olarak çalıştırılmamalıdır. Normal kullanıcı ile çalıştırın." "$RED"
        exit 1
    fi
}

# Function to check internet connection
check_internet() {
    if ! ping -c 1 google.com &> /dev/null; then
        print_message "⚠️  İnternet bağlantınızı kontrol edin!" "$YELLOW"
        return 1
    fi
    return 0
}

# Function to set password with visible input
set_password() {
    local user="$1"
    local prompt="$2"
    
    while true; do
        echo ""
        print_message "$prompt" "$BLUE"
        print_message "Parola görünür olacak şekilde yazın:" "$YELLOW"
        read -r PASSWORD
        print_message "Parolayı tekrar girin:" "$YELLOW"
        read -r PASSWORD2
        
        if [ "$PASSWORD" == "$PASSWORD2" ] && [ -n "$PASSWORD" ]; then
            echo "$user:$PASSWORD" | sudo chpasswd
            if [ $? -eq 0 ]; then
                print_message "✅ Parola başarıyla ayarlandı" "$GREEN"
                return 0
            else
                print_message "❌ Parola ayarlanamadı, tekrar deneyin" "$RED"
            fi
        else
            print_message "❌ Parolalar eşleşmiyor veya boş! Tekrar deneyin." "$RED"
        fi
    done
}

# Display header
print_message "\n🎯 ============================================" "$PURPLE"
print_message "     Ubuntu Server SSH Kurulum Scripti" "$PURPLE"
print_message "============================================\n" "$PURPLE"

# Check initial conditions
check_root
check_internet

# Display current system information
print_message "📊 SİSTEM BİLGİLERİ" "$CYAN"
print_message "────────────────────" "$BLUE"
CURRENT_USER=$(whoami)
print_message "👤 Mevcut Kullanıcı: $CURRENT_USER" "$YELLOW"
CURRENT_HOSTNAME=$(hostname)
print_message "🏷️  Mevcut Hostname: $CURRENT_HOSTNAME" "$YELLOW"
ROOT_STATUS=$(sudo passwd -S root | awk '{print $2}')
print_message "👑 Root Durumu: $ROOT_STATUS" "$YELLOW"
IP_ADDRESS=$(hostname -I | awk '{print $1}')
print_message "🌐 Yerel IP: $IP_ADDRESS" "$YELLOW"
echo ""

# Ask to change hostname
print_message "🔧 HOSTNAME AYARLARI" "$CYAN"
print_message "─────────────────────" "$BLUE"
read -p "🏷️  Hostname'i değiştirmek istiyor musunuz? (y/N): " CHANGE_HOSTNAME

if [[ $CHANGE_HOSTNAME =~ ^[Yy]$ ]]; then
    read -p "✨ Yeni hostname girin: " NEW_HOSTNAME
    if [ ! -z "$NEW_HOSTNAME" ]; then
        sudo hostnamectl set-hostname "$NEW_HOSTNAME"
        echo "127.0.0.1 $NEW_HOSTNAME" | sudo tee -a /etc/hosts
        print_message "✅ Hostname '$NEW_HOSTNAME' olarak değiştirildi" "$GREEN"
        SERVER_HOSTNAME="$NEW_HOSTNAME"
    else
        SERVER_HOSTNAME="$CURRENT_HOSTNAME"
    fi
else
    SERVER_HOSTNAME="$CURRENT_HOSTNAME"
fi

# Force new root password
print_message "\n🔐 ROOT PAROLA DEĞİŞİKLİĞİ" "$CYAN"
print_message "──────────────────────────" "$BLUE"
print_message "⚠️  Root parolasını değiştirmeniz ZORUNLUDUR!" "$RED"
set_password "root" "🔑 Yeni ROOT parolasını girin:"

# Create new sudo user
print_message "\n👥 YENİ KULLANICI OLUŞTURMA" "$CYAN"
print_message "──────────────────────────" "$BLUE"
print_message "🔒 Güvenlik için yeni bir kullanıcı oluşturulacak" "$YELLOW"
while true; do
    read -p "✨ Yeni kullanıcı adı girin: " NEW_USER
    if [ -z "$NEW_USER" ]; then
        print_message "❌ Kullanıcı adı boş olamaz!" "$RED"
        continue
    fi
    if id "$NEW_USER" &>/dev/null; then
        print_message "❌ Bu kullanıcı zaten var!" "$RED"
        continue
    fi
    break
done

# Create new user without password first
sudo adduser --disabled-password --gecos "" "$NEW_USER" > /dev/null 2>&1
sudo usermod -aG sudo "$NEW_USER"

# Set password for new user
set_password "$NEW_USER" "🔑 Yeni '$NEW_USER' kullanıcısı için parola girin:"

print_message "✅ Kullanıcı '$NEW_USER' oluşturuldu ve sudo grubuna eklendi" "$GREEN"

# Disable root password login
print_message "\n🔒 ROOT GİRİŞİ KAPATILIYOR" "$CYAN"
print_message "──────────────────────────" "$BLUE"
sudo passwd -l root
print_message "✅ Root parola ile giriş devre dışı bırakıldı (kullanıcı silinmedi)" "$GREEN"

# System updates
print_message "\n📦 SİSTEM GÜNCELLEMELERİ" "$CYAN"
print_message "────────────────────────" "$BLUE"
print_message "🔄 Sistem paketleri güncelleniyor..." "$YELLOW"
sudo apt update && sudo apt upgrade -y
print_message "✅ Sistem güncellemeleri tamamlandı" "$GREEN"

# Configure automatic security updates
print_message "\n🛡️  OTOMATİK GÜVENLİK GÜNCELLEMELERİ" "$CYAN"
print_message "──────────────────────────────────" "$BLUE"
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades -f noninteractive
print_message "✅ Otomatik güvenlik güncellemeleri yapılandırıldı" "$GREEN"

# Install required packages
print_message "\n📦 GEREKLİ PAKET KURULUMU" "$CYAN"
print_message "─────────────────────────" "$BLUE"
print_message "🔧 Aşağıdaki paketler kuruluyor:" "$YELLOW"
echo "• openssh-server"
echo "• ufw (güvenlik duvarı)"
echo "• fail2ban (brute-force koruması)"
sudo apt install -y openssh-server ufw fail2ban
print_message "✅ Tüm paketler başarıyla kuruldu" "$GREEN"

# Backup original SSH config
print_message "\n💾 SSH KONFİGÜRASYON YEDEĞİ" "$CYAN"
print_message "───────────────────────────" "$BLUE"
BACKUP_FILE="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
sudo cp /etc/ssh/sshd_config "$BACKUP_FILE"
print_message "✅ SSH konfigürasyonu yedeklendi: $BACKUP_FILE" "$GREEN"

# Configure SSH with port 2222
print_message "\n🔧 SSH KONFİGÜRASYONU" "$CYAN"
print_message "──────────────────────" "$BLUE"
SSH_PORT="2222"
print_message "🚪 SSH portu 2222 olarak ayarlanıyor..." "$YELLOW"

# Create new SSH config
sudo tee /etc/ssh/sshd_config > /dev/null << EOF
# SSH Server Configuration
Port $SSH_PORT
Protocol 2

# Authentication
LoginGraceTime 120
PermitRootLogin no
StrictModes yes

# Security
MaxAuthTries 3
MaxSessions 3
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel INFO

# User restrictions
AllowUsers $NEW_USER

# Crypto
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Key exchange algorithms
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# Ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# MACs
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com

# Other settings
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
UsePAM yes
UseDNS no
Compression no

# Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

print_message "✅ SSH portu $SSH_PORT olarak ayarlandı" "$GREEN"
print_message "✅ Maksimum eşzamanlı bağlantı: 3" "$GREEN"

# Ask for authentication method
print_message "\n🔐 KİMLİK DOĞRULAMA YÖNTEMİ" "$CYAN"
print_message "───────────────────────────" "$BLUE"
print_message "Lütfen bir kimlik doğrulama yöntemi seçin:" "$YELLOW"
echo ""
echo "1) 🔓 Parola ile giriş (önerilmez, güvenlik: ⭐)"
echo "2) 🔐 Parola + 2FA ile giriş (önemli, güvenlik: ⭐⭐)"
echo "3) 🔑 SSH Anahtarı ile giriş (önerilir, güvenlik: ⭐⭐⭐⭐)"
echo "4) 🛡️  SSH Anahtarı + 2FA ile giriş (tavsiye edilen, güvenlik: ⭐⭐⭐⭐⭐)"
echo ""
read -p "Seçiminiz (1/2/3/4): " AUTH_CHOICE

case $AUTH_CHOICE in
    1)
        # Password only
        print_message "\n🔓 PAROLA İLE GİRİŞ SEÇİLDİ" "$YELLOW"
        AUTH_METHOD="Parola"
        SECURITY_LEVEL="⭐"
        PASSWORD_AUTH="yes"
        PUBKEY_AUTH="no"
        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
        print_message "⚠️  UYARI: Parola ile giriş güvenli değildir!" "$RED"
        ;;
    2)
        # Password + 2FA
        print_message "\n🔐 PAROLA + 2FA SEÇİLDİ" "$GREEN"
        AUTH_METHOD="Parola + 2FA"
        SECURITY_LEVEL="⭐⭐"
        PASSWORD_AUTH="yes"
        PUBKEY_AUTH="no"
        
        # Install 2FA packages
        print_message "🔧 2FA paketleri kuruluyor..." "$YELLOW"
        sudo apt install -y libpam-google-authenticator
        
        # Configure PAM for 2FA - ONLY for SSH
        sudo tee /etc/pam.d/sshd-2fa > /dev/null << 'PAM_EOF'
# PAM configuration for SSH with 2FA
# Disable standard password auth for SSH
auth requisite pam_succeed_if.so uid >= 1000 quiet_success
# Require Google Authenticator
auth required pam_google_authenticator.so
# Allow access if 2FA succeeds
auth required pam_permit.so
PAM_EOF
        
        # Backup original PAM config
        sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.backup
        
        # Replace PAM config for SSH
        sudo cp /etc/pam.d/sshd-2fa /etc/pam.d/sshd
        
        # Configure SSH for 2FA
        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sudo sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
        sudo sed -i 's/UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
        
        # Generate 2FA for user
        print_message "🔑 2FA kurulumu yapılıyor..." "$YELLOW"
        print_message "📱 Aşağıdaki QR kodu Google Authenticator uygulamasına taratın:" "$BLUE"
        sudo -u "$NEW_USER" google-authenticator -t -d -f -r 3 -R 30 -w 3 -Q UTF8
        
        print_message "✅ 2FA yapılandırıldı. Her girişte Google Authenticator kodu gerekecek." "$GREEN"
        ;;
    3)
        # SSH Key only
        print_message "\n🔑 SSH ANAHTARI İLE GİRİŞ SEÇİLDİ" "$GREEN"
        AUTH_METHOD="SSH Anahtarı"
        SECURITY_LEVEL="⭐⭐⭐⭐"
        PASSWORD_AUTH="no"
        PUBKEY_AUTH="yes"
        
        # Create SSH keys with simple names
        KEY_NAME="$SERVER_HOSTNAME"
        KEY_PATH="/home/$NEW_USER/.ssh/$KEY_NAME"
        
        # Create .ssh directory
        sudo -u "$NEW_USER" mkdir -p "/home/$NEW_USER/.ssh"
        
        # Generate Ed25519 key pair
        sudo -u "$NEW_USER" ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "$NEW_USER@$SERVER_HOSTNAME"
        
        # Set proper permissions
        sudo chmod 700 "/home/$NEW_USER/.ssh"
        sudo chmod 600 "$KEY_PATH"
        sudo chmod 644 "$KEY_PATH.pub"
        
        # Add public key to authorized_keys
        sudo cat "$KEY_PATH.pub" | sudo -u "$NEW_USER" tee -a "/home/$NEW_USER/.ssh/authorized_keys" > /dev/null
        sudo chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
        
        # Configure SSH for key auth only
        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        
        print_message "✅ SSH anahtar çifti oluşturuldu:" "$GREEN"
        print_message "   • Private Key: $KEY_NAME" "$CYAN"
        print_message "   • Public Key: $KEY_NAME.pub" "$CYAN"
        ;;
    4)
        # SSH Key + 2FA
        print_message "\n🛡️  SSH ANAHTARI + 2FA SEÇİLDİ" "$GREEN"
        AUTH_METHOD="SSH Anahtarı + 2FA"
        SECURITY_LEVEL="⭐⭐⭐⭐⭐"
        PASSWORD_AUTH="no"
        PUBKEY_AUTH="yes"
        
        # Create SSH keys with simple names
        KEY_NAME="$SERVER_HOSTNAME"
        KEY_PATH="/home/$NEW_USER/.ssh/$KEY_NAME"
        
        # Create .ssh directory
        sudo -u "$NEW_USER" mkdir -p "/home/$NEW_USER/.ssh"
        
        # Generate Ed25519 key pair
        sudo -u "$NEW_USER" ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "$NEW_USER@$SERVER_HOSTNAME"
        
        # Set proper permissions
        sudo chmod 700 "/home/$NEW_USER/.ssh"
        sudo chmod 600 "$KEY_PATH"
        sudo chmod 644 "$KEY_PATH.pub"
        
        # Add public key to authorized_keys
        sudo cat "$KEY_PATH.pub" | sudo -u "$NEW_USER" tee -a "/home/$NEW_USER/.ssh/authorized_keys" > /dev/null
        sudo chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
        
        # Install 2FA packages
        print_message "🔧 2FA paketleri kuruluyor..." "$YELLOW"
        sudo apt install -y libpam-google-authenticator
        
        # Configure PAM for 2FA - ONLY for SSH
        sudo tee /etc/pam.d/sshd-2fa > /dev/null << 'PAM_EOF'
# PAM configuration for SSH with 2FA
# Disable standard password auth for SSH
auth requisite pam_succeed_if.so uid >= 1000 quiet_success
# Require Google Authenticator
auth required pam_google_authenticator.so
# Allow access if 2FA succeeds
auth required pam_permit.so
PAM_EOF
        
        # Backup original PAM config
        sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.backup
        
        # Replace PAM config for SSH
        sudo cp /etc/pam.d/sshd-2fa /etc/pam.d/sshd
        
        # Configure SSH for key auth and 2FA
        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        sudo sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
        sudo sed -i 's/UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
        
        # Generate 2FA for user
        print_message "🔑 2FA kurulumu yapılıyor..." "$YELLOW"
        print_message "📱 Aşağıdaki QR kodu Google Authenticator uygulamasına taratın:" "$BLUE"
        sudo -u "$NEW_USER" google-authenticator -t -d -f -r 3 -R 30 -w 3 -Q UTF8
        
        print_message "✅ SSH anahtar çifti oluşturuldu:" "$GREEN"
        print_message "   • Private Key: $KEY_NAME" "$CYAN"
        print_message "   • Public Key: $KEY_NAME.pub" "$CYAN"
        print_message "✅ 2FA yapılandırıldı. Her girişte SSH anahtarı + Google Authenticator kodu gerekecek." "$GREEN"
        ;;
    *)
        print_message "\n❌ Geçersiz seçim! Varsayılan olarak SSH Anahtarı kullanılacak." "$RED"
        AUTH_METHOD="SSH Anahtarı"
        SECURITY_LEVEL="⭐⭐⭐⭐"
        PASSWORD_AUTH="no"
        PUBKEY_AUTH="yes"
        
        # Create SSH keys
        KEY_NAME="$SERVER_HOSTNAME"
        KEY_PATH="/home/$NEW_USER/.ssh/$KEY_NAME"
        sudo -u "$NEW_USER" mkdir -p "/home/$NEW_USER/.ssh"
        sudo -u "$NEW_USER" ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "$NEW_USER@$SERVER_HOSTNAME"
        sudo cat "$KEY_PATH.pub" | sudo -u "$NEW_USER" tee -a "/home/$NEW_USER/.ssh/authorized_keys" > /dev/null
        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        ;;
esac

# Add authentication settings to sshd_config - CRITICAL FIX for 2FA
print_message "\n🔧 SSH KİMLİK DOĞRULAMA AYARLARI" "$CYAN"
print_message "────────────────────────────────" "$BLUE"

case $AUTH_CHOICE in
    1)
        # Password only
        AUTH_METHODS="password"
        ;;
    2)
        # Password + 2FA
        AUTH_METHODS="password,keyboard-interactive"
        ;;
    3)
        # SSH Key only
        AUTH_METHODS="publickey"
        ;;
    4)
        # SSH Key + 2FA
        AUTH_METHODS="publickey,keyboard-interactive"
        ;;
    *)
        AUTH_METHODS="publickey"
        ;;
esac

sudo tee -a /etc/ssh/sshd_config > /dev/null << EOF

# Authentication settings added by setup script
PasswordAuthentication $PASSWORD_AUTH
PubkeyAuthentication $PUBKEY_AUTH
ChallengeResponseAuthentication yes
UsePAM yes
AuthenticationMethods $AUTH_METHODS
EOF

print_message "✅ Kimlik doğrulama yöntemleri ayarlandı: $AUTH_METHODS" "$GREEN"

# Configure UFW firewall
print_message "\n🔥 GÜVENLİK DUVARI (UFW) KONFİGÜRASYONU" "$CYAN"
print_message "─────────────────────────────────────" "$BLUE"
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow $SSH_PORT/tcp
echo "y" | sudo ufw enable
print_message "✅ Güvenlik duvarı aktif edildi" "$GREEN"
print_message "✅ Sadece $SSH_PORT portu açık" "$GREEN"

# Configure Fail2Ban
print_message "\n🛡️  FAIL2BAN KONFİGÜRASYONU" "$CYAN"
print_message "─────────────────────────" "$BLUE"
sudo tee /etc/fail2ban/jail.local > /dev/null << EOF
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

sudo systemctl restart fail2ban
sudo systemctl enable fail2ban
print_message "✅ Fail2Ban yapılandırıldı" "$GREEN"
print_message "   • Maksimum deneme: 5" "$CYAN"
print_message "   • Ban süresi: 3600 saniye" "$CYAN"
print_message "   • Zaman penceresi: 600 saniye" "$CYAN"

# Restart SSH service
print_message "\n🔄 SSH SERVİSİ YENİDEN BAŞLATILIYOR" "$CYAN"
print_message "─────────────────────────────────" "$BLUE"
sudo systemctl restart ssh
sudo systemctl enable ssh
print_message "✅ SSH servisi yeniden başlatıldı" "$GREEN"

# Get public IP
print_message "\n🌐 AĞ BİLGİLERİ ALINIYOR" "$CYAN"
print_message "────────────────────────" "$BLUE"
PUBLIC_IP=$(curl -s icanhazip.com || echo "Bilinmiyor")
print_message "✅ Ağ bilgileri alındı" "$GREEN"

# Create Linux folder and setup instructions for client
print_message "\n📁 İSTEMCİ KURULUM TALİMATLARI" "$CYAN"
print_message "─────────────────────────────" "$BLUE"

if [[ $AUTH_CHOICE == "3" || $AUTH_CHOICE == "4" || -z "$AUTH_CHOICE" ]]; then
    # Display private key content
    print_message "🔐 PRIVATE KEY İÇERİĞİ:" "$YELLOW"
    print_message "───────────────────────" "$BLUE"
    echo ""
    sudo cat "$KEY_PATH"
    echo ""
    print_message "───────────────────────" "$BLUE"
    
    # Create client setup instructions
    CLIENT_SCRIPT="/home/$NEW_USER/linux/ssh_setup_client.sh"
    sudo -u "$NEW_USER" mkdir -p "/home/$NEW_USER/linux"
    
    sudo tee "$CLIENT_SCRIPT" > /dev/null << EOF
#!/bin/bash

# Client SSH Setup Script
echo "🚀 Linux SSH Kurulum Scripti"

# Create linux directory if it doesn't exist
mkdir -p ~/linux
cd ~/linux

# Create private key file
cat > "$SERVER_HOSTNAME" << 'PRIVATE_KEY'
$(sudo cat "$KEY_PATH")
PRIVATE_KEY

# Set proper permissions
chmod 600 "$SERVER_HOSTNAME"

echo ""
echo "✅ Kurulum tamamlandı!"
echo ""
echo "📋 YAPILAN İŞLEMLER:"
echo "1. Private key ~/linux/$SERVER_HOSTNAME dosyasına kaydedildi"
echo "2. Dosya izinleri ayarlandı (chmod 600)"
echo ""
EOF

    sudo chmod +x "$CLIENT_SCRIPT"
    
    print_message "📋 KURULUM TALİMATLARI:" "$GREEN"
    print_message "──────────────────────" "$BLUE"
    print_message "İstemci bilgisayarınızda şu adımları izleyin:" "$YELLOW"
    echo ""
    print_message "1. 🗂️  'linux' klasörü oluşturun:" "$CYAN"
    print_message "   mkdir ~/linux && cd ~/linux" "$GREEN"
    echo ""
    print_message "2. 📝 Private key dosyası oluşturun:" "$CYAN"
    print_message "   nano $SERVER_HOSTNAME" "$GREEN"
    print_message "   Yukarıdaki private key içeriğini yapıştırın ve Ctrl+X, Y, Enter" "$YELLOW"
    echo ""
    print_message "3. 🔐 Dosya izinlerini ayarlayın:" "$CYAN"
    print_message "   chmod 600 $SERVER_HOSTNAME" "$GREEN"
    echo ""
fi

# Create summary
print_message "\n🎯 KURULUM ÖZETİ" "$PURPLE"
print_message "════════════════════════════════════════════════════════════════════════════════" "$PURPLE"
echo ""
print_message "📊 SİSTEM BİLGİLERİ:" "$CYAN"
print_message "• Sunucu Adı:       $SERVER_HOSTNAME" "$YELLOW"
print_message "• Yeni Kullanıcı:   $NEW_USER" "$YELLOW"
print_message "• SSH Port:         $SSH_PORT" "$YELLOW"
print_message "• Yerel IP:         $IP_ADDRESS" "$YELLOW"
print_message "• Genel IP:         $PUBLIC_IP" "$YELLOW"
echo ""
print_message "🔐 GÜVENLİK AYARLARI:" "$CYAN"
print_message "• Kimlik Doğrulama: $AUTH_METHOD" "$YELLOW"
print_message "• Güvenlik Seviyesi: $SECURITY_LEVEL" "$YELLOW"
print_message "• Root Girişi:      Devre Dışı" "$YELLOW"
print_message "• Max Bağlantı:     3 eşzamanlı" "$YELLOW"
print_message "• Fail2Ban:         Aktif (5 deneme/3600s ban)" "$YELLOW"
echo ""

if [[ $AUTH_CHOICE == "3" || $AUTH_CHOICE == "4" || -z "$AUTH_CHOICE" ]]; then
    print_message "🔑 SSH ANAHTAR BİLGİLERİ:" "$CYAN"
    print_message "• Private Key:     $SERVER_HOSTNAME" "$YELLOW"
    print_message "• Public Key:      $SERVER_HOSTNAME.pub" "$YELLOW"
    print_message "• Key Konumu:     ~/.ssh/$SERVER_HOSTNAME" "$YELLOW"
    print_message "• Public Key Yeri: ~/.ssh/authorized_keys" "$YELLOW"
    echo ""
fi

print_message "🚀 BAĞLANTI KOMUTLARI:" "$CYAN"
if [[ $AUTH_CHOICE == "1" ]]; then
    print_message "• ssh -p $SSH_PORT $NEW_USER@$IP_ADDRESS" "$GREEN"
    if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
        print_message "• veya: ssh -p $SSH_PORT $NEW_USER@$PUBLIC_IP" "$GREEN"
    fi
elif [[ $AUTH_CHOICE == "2" ]]; then
    print_message "• ssh -p $SSH_PORT $NEW_USER@$IP_ADDRESS" "$GREEN"
    if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
        print_message "• veya: ssh -p $SSH_PORT $NEW_USER@$PUBLIC_IP" "$GREEN"
    fi
    print_message "📱 Her girişte Google Authenticator kodu gerekecek" "$YELLOW"
else
    print_message "• ssh -p $SSH_PORT -i ~/linux/$SERVER_HOSTNAME $NEW_USER@$IP_ADDRESS" "$GREEN"
    if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
        print_message "• veya: ssh -p $SSH_PORT -i ~/linux/$SERVER_HOSTNAME $NEW_USER@$PUBLIC_IP" "$GREEN"
    fi
    if [[ $AUTH_CHOICE == "4" ]]; then
        print_message "📱 Her girişte Google Authenticator kodu gerekecek (SSH key'den sonra)" "$YELLOW"
    fi
fi
echo ""
print_message "🔧 2FA NOTLARI:" "$PURPLE"
if [[ $AUTH_CHOICE == "2" || $AUTH_CHOICE == "4" ]]; then
    print_message "• SSH + 2FA her bağlantıda 2FA kodu ister" "$YELLOW"
    print_message "• QR kodu Google Authenticator uygulamasına taratıldı" "$YELLOW"
    print_message "• 2FA kodları 30 saniyede bir değişir" "$YELLOW"
    print_message "• Yedek kurtarma kodlarını güvenli bir yerde saklayın" "$YELLOW"
fi
echo ""
print_message "🛡️  GÜVENLİK NOTLARI:" "$RED"
print_message "• Root parola ile giriş devre dışı bırakıldı" "$YELLOW"
print_message "• Yalnızca $NEW_USER kullanıcısı SSH ile bağlanabilir" "$YELLOW"
print_message "• Fail2Ban aktif - 5 başarısız denemede 1 saat ban" "$YELLOW"
print_message "• Güvenlik duvarı aktif - sadece port $SSH_PORT açık" "$YELLOW"
print_message "• Otomatik güvenlik güncellemeleri aktif" "$YELLOW"
print_message "• Parola görünür şekilde ayarlanır, kopyala-yapıştır desteklenir" "$YELLOW"
echo ""
print_message "✅ AYARLAR KALICIDIR ve sunucu yeniden başlatıldığında korunur" "$GREEN"
print_message "\n🎉 KURULUM TAMAMLANDI! Sunucunuza güvenli bir şekilde bağlanabilirsiniz." "$GREEN"
print_message "════════════════════════════════════════════════════════════════════════════════" "$PURPLE"

# Save summary to file
SUMMARY_FILE="/home/$NEW_USER/ssh_kurulum_ozeti.txt"
sudo tee "$SUMMARY_FILE" > /dev/null << EOF
SSH KURULUM ÖZETİ - $(date)
════════════════════════════════════════════════════════════════════════════════

SİSTEM BİLGİLERİ:
• Sunucu Adı:       $SERVER_HOSTNAME
• Kullanıcı:        $NEW_USER
• SSH Port:         $SSH_PORT
• Yerel IP:         $IP_ADDRESS
• Genel IP:         $PUBLIC_IP

GÜVENLİK AYARLARI:
• Kimlik Doğrulama: $AUTH_METHOD
• Güvenlik Seviyesi: $SECURITY_LEVEL
• Root Girişi:      Devre Dışı
• Max Bağlantı:     3 eşzamanlı
• Fail2Ban:         Aktif (5 deneme/3600s ban)

$(if [[ $AUTH_CHOICE == "3" || $AUTH_CHOICE == "4" || -z "$AUTH_CHOICE" ]]; then
echo "SSH ANAHTAR BİLGİLERİ:"
echo "• Private Key:     $SERVER_HOSTNAME"
echo "• Public Key:      $SERVER_HOSTNAME.pub"
echo ""
fi)

BAĞLANTI KOMUTLARI:
$(if [[ $AUTH_CHOICE == "1" || $AUTH_CHOICE == "2" ]]; then
    echo "ssh -p $SSH_PORT $NEW_USER@$IP_ADDRESS"
    if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
        echo "veya: ssh -p $SSH_PORT $NEW_USER@$PUBLIC_IP"
    fi
else
    echo "ssh -p $SSH_PORT -i ~/linux/$SERVER_HOSTNAME $NEW_USER@$IP_ADDRESS"
    if [ "$PUBLIC_IP" != "Bilinmiyor" ]; then
        echo "veya: ssh -p $SSH_PORT -i ~/linux/$SERVER_HOSTNAME $NEW_USER@$PUBLIC_IP"
    fi
fi)

$(if [[ $AUTH_CHOICE == "2" || $AUTH_CHOICE == "4" ]]; then
echo ""
echo "2FA NOTLARI:"
echo "• SSH + 2FA her bağlantıda Google Authenticator kodu ister"
echo "• QR kodu Google Authenticator uygulamasına taratıldı"
echo "• 2FA kodları 30 saniyede bir değişir"
echo "• Yedek kurtarma kodlarını güvenli bir yerde saklayın"
fi)

KURULUM TARİHİ: $(date)
EOF

print_message "\n📄 Detaylı özet dosyası: $SUMMARY_FILE" "$BLUE"
