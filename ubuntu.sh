#!/bin/bash

# =============================================================================
# GÜVENLİK AYARLARI VE HATA YAKALAMA
# =============================================================================
set -Eeuo pipefail
trap 'echo -e "\033[0;31m❌ Hata oluştu. Script durduruldu.\033[0m"' ERR
trap 'echo -e "\033[0;31m\n❌ Kullanıcı tarafından iptal edildi.\033[0m"' INT

# =============================================================================
# DEĞİŞKENLER VE KONSTANTLAR
# =============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly SSH_BAK_FILE="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
readonly SSH_CUSTOM_CONF="/etc/ssh/sshd_config.d/99-hardening.conf"
readonly FAIL2BAN_CONF="/etc/fail2ban/jail.local"
readonly LOG_FILE="/tmp/ssh-setup-$(date +%Y%m%d_%H%M%S).log"

# =============================================================================
# FONKSİYONLAR
# =============================================================================

# Renkli mesaj fonksiyonu
print_message() {
    echo -e "${2}${1}${NC}"
}

# Log fonksiyonu
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE" > /dev/null
}

# Hata fonksiyonu
error_exit() {
    print_message "❌ $1" "$RED"
    log_message "HATA: $1"
    exit 1
}

# Kontrol fonksiyonu
check_command() {
    if ! command -v "$1" &> /dev/null; then
        error_exit "$1 komutu bulunamadı. Lütfen kurun: sudo apt install $1"
    fi
}

# Root kontrolü
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error_exit "Bu script root olarak çalıştırılmamalıdır."
    fi
}

# İnternet kontrolü
check_internet() {
    if ! ping -c 1 -W 2 google.com &> /dev/null; then
        print_message "⚠️  İnternet bağlantısı yok. Bazı işlemler atlanacak." "$YELLOW"
        return 1
    fi
    return 0
}

# Sistem bilgilerini göster
show_system_info() {
    print_message "\n📊 SİSTEM BİLGİLERİ" "$CYAN"
    print_message "────────────────────" "$BLUE"
    print_message "• Mevcut Kullanıcı: $(whoami)" "$YELLOW"
    print_message "• Hostname: $(hostname)" "$YELLOW"
    print_message "• Dağıtım: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')" "$YELLOW"
    print_message "• Çekirdek: $(uname -r)" "$YELLOW"
    print_message "• Yerel IP: $(hostname -I | awk '{print $1}')" "$YELLOW"
}

# Root parola yönetimi
manage_root_password() {
    print_message "\n🔐 ROOT PAROLA YÖNETİMİ" "$CYAN"
    print_message "───────────────────────" "$BLUE"
    
    echo ""
    echo "1) Varsayılan root parolasını değiştir (önerilen)"
    echo "2) Mevcut root parolasını koru (riskli)"
    echo ""
    
    while true; do
        read -p "Seçiminiz (1/2): " root_choice
        
        case $root_choice in
            1)
                print_message "\n🔑 Yeni ROOT parolasını girin:" "$BLUE"
                print_message "(Parola görünmez, kopyala-yapıştır desteklenir)" "$YELLOW"
                read -rs root_pass1
                echo ""
                print_message "Parolayı tekrar girin:" "$YELLOW"
                read -rs root_pass2
                echo ""
                
                if [[ "$root_pass1" == "$root_pass2" && -n "$root_pass1" ]]; then
                    echo "root:$root_pass1" | sudo chpasswd
                    if [[ $? -eq 0 ]]; then
                        print_message "✅ Root parolası başarıyla değiştirildi" "$GREEN"
                        log_message "Root parolası değiştirildi"
                        break
                    else
                        print_message "❌ Parola değiştirilemedi" "$RED"
                    fi
                else
                    print_message "❌ Parolalar eşleşmiyor veya boş!" "$RED"
                fi
                ;;
            2)
                print_message "⚠️  Root parolasını değiştirmediğiniz için güvenlik riski oluşabilir!" "$RED"
                log_message "Root parolası değiştirilmedi"
                break
                ;;
            *)
                print_message "❌ Geçersiz seçim!" "$RED"
                ;;
        esac
    done
}

# Kullanıcı oluşturma
create_user() {
    print_message "\n👥 YENİ KULLANICI OLUŞTURMA" "$CYAN"
    print_message "──────────────────────────" "$BLUE"
    
    while true; do
        read -p "✨ Yeni kullanıcı adı girin: " NEW_USER
        
        if [[ -z "$NEW_USER" ]]; then
            print_message "❌ Kullanıcı adı boş olamaz!" "$RED"
            continue
        fi
        
        if id "$NEW_USER" &>/dev/null; then
            print_message "ℹ️  Kullanıcı '$NEW_USER' zaten var. Mevcut kullanıcıyı kullanacaksınız." "$YELLOW"
            break
        fi
        
        break
    done
    
    # Kullanıcı yoksa oluştur
    if ! id "$NEW_USER" &>/dev/null; then
        sudo adduser --disabled-password --gecos "" "$NEW_USER" > /dev/null 2>&1
        
        print_message "\n🔑 '$NEW_USER' için parola belirleyin:" "$BLUE"
        print_message "(Parola görünmez, kopyala-yapıştır desteklenir)" "$YELLOW"
        read -rs user_pass1
        echo ""
        print_message "Parolayı tekrar girin:" "$YELLOW"
        read -rs user_pass2
        echo ""
        
        if [[ "$user_pass1" == "$user_pass2" && -n "$user_pass1" ]]; then
            echo "$NEW_USER:$user_pass1" | sudo chpasswd
            print_message "✅ Kullanıcı '$NEW_USER' oluşturuldu ve parola ayarlandı" "$GREEN"
            log_message "Kullanıcı $NEW_USER oluşturuldu"
        else
            error_exit "Parolalar eşleşmiyor veya boş!"
        fi
    fi
    
    # Kullanıcıyı gruplara ekle
    sudo usermod -aG sudo "$NEW_USER"
    sudo groupadd -f sshusers
    sudo usermod -aG sshusers "$NEW_USER"
    
    print_message "✅ Kullanıcı '$NEW_USER' sudo ve sshusers gruplarına eklendi" "$GREEN"
}

# SSH port ayarı
configure_ssh_port() {
    print_message "\n🚪 SSH PORT AYARI" "$CYAN"
    print_message "─────────────────" "$BLUE"
    
    CURRENT_PORT=$(sudo grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    print_message "Mevcut SSH Port: $CURRENT_PORT" "$YELLOW"
    
    while true; do
        read -p "Yeni SSH portu (1024-65535, varsayılan: 2222): " SSH_PORT
        SSH_PORT=${SSH_PORT:-2222}
        
        if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1024 ] && [ "$SSH_PORT" -le 65535 ]; then
            if [ "$SSH_PORT" -lt 1024 ]; then
                print_message "⚠️  1024'ten küçük portlar root gerektirir. Önerilmez!" "$YELLOW"
            fi
            break
        else
            print_message "❌ Geçersiz port! 1024-65535 arasında olmalı." "$RED"
        fi
    done
    
    print_message "✅ SSH portu $SSH_PORT olarak ayarlandı" "$GREEN"
    log_message "SSH portu $SSH_PORT olarak ayarlandı"
}

# Sistem güncellemeleri
update_system() {
    print_message "\n📦 SİSTEM GÜNCELLEMELERİ" "$CYAN"
    print_message "────────────────────────" "$BLUE"
    
    print_message "🔄 Paket listesi güncelleniyor..." "$YELLOW"
    sudo apt update >> "$LOG_FILE" 2>&1
    
    print_message "⚡ Sistem güncelleniyor..." "$YELLOW"
    sudo apt upgrade -y >> "$LOG_FILE" 2>&1
    
    print_message "🧹 Temizlik yapılıyor..." "$YELLOW"
    sudo apt autoremove -y >> "$LOG_FILE" 2>&1
    
    print_message "✅ Sistem güncellemeleri tamamlandı" "$GREEN"
}

# Güvenlik güncellemeleri
configure_security_updates() {
    print_message "\n🛡️  OTOMATİK GÜVENLİK GÜNCELLEMELERİ" "$CYAN"
    print_message "──────────────────────────────────" "$BLUE"
    
    sudo apt install -y unattended-upgrades >> "$LOG_FILE" 2>&1
    
    sudo tee /etc/apt/apt.conf.d/50unattended-upgrades > /dev/null << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    
    sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
    
    print_message "✅ Otomatik güvenlik güncellemeleri yapılandırıldı" "$GREEN"
}

# Paket kurulumu
install_packages() {
    print_message "\n📦 GEREKLİ PAKET KURULUMU" "$CYAN"
    print_message "─────────────────────────" "$BLUE"
    
    local packages=("openssh-server" "ufw" "fail2ban")
    
    for pkg in "${packages[@]}"; do
        if dpkg -l | grep -q "^ii  $pkg "; then
            print_message "✅ $pkg zaten kurulu" "$GREEN"
        else
            print_message "📦 $pkg kuruluyor..." "$YELLOW"
            sudo apt install -y "$pkg" >> "$LOG_FILE" 2>&1
            print_message "✅ $pkg kuruldu" "$GREEN"
        fi
    done
}

# SSH yapılandırması
configure_ssh() {
    print_message "\n🔧 SSH KONFİGÜRASYONU" "$CYAN"
    print_message "──────────────────────" "$BLUE"
    
    # SSH config dizinini oluştur
    sudo mkdir -p /etc/ssh/sshd_config.d
    
    # Mevcut config'i yedekle
    if [[ -f /etc/ssh/sshd_config ]]; then
        sudo cp /etc/ssh/sshd_config "$SSH_BAK_FILE"
        print_message "📋 SSH config yedeklendi: $SSH_BAK_FILE" "$GREEN"
    fi
    
    # Kimlik doğrulama yöntemi seçimi
    print_message "\n🔐 KİMLİK DOĞRULAMA YÖNTEMİ" "$BLUE"
    echo ""
    echo "1) 🔓 Parola ile giriş (önerilmez, güvenlik: ⭐)"
    echo "2) 🔐 Parola + 2FA ile giriş (önemli, güvenlik: ⭐⭐)"
    echo "3) 🔑 SSH Anahtarı ile giriş (önerilir, güvenlik: ⭐⭐⭐⭐)"
    echo "4) 🛡️  SSH Anahtarı + 2FA ile giriş (tavsiye edilen, güvenlik: ⭐⭐⭐⭐⭐)"
    echo ""
    
    while true; do
        read -p "Seçiminiz (1/2/3/4): " AUTH_CHOICE
        
        case $AUTH_CHOICE in
            1)
                AUTH_METHOD="Parola"
                SECURITY_LEVEL="⭐"
                PASSWORD_AUTH="yes"
                PUBKEY_AUTH="no"
                ;;
            2)
                AUTH_METHOD="Parola + 2FA"
                SECURITY_LEVEL="⭐⭐"
                PASSWORD_AUTH="yes"
                PUBKEY_AUTH="no"
                ;;
            3)
                AUTH_METHOD="SSH Anahtarı"
                SECURITY_LEVEL="⭐⭐⭐⭐"
                PASSWORD_AUTH="no"
                PUBKEY_AUTH="yes"
                ;;
            4)
                AUTH_METHOD="SSH Anahtarı + 2FA"
                SECURITY_LEVEL="⭐⭐⭐⭐⭐"
                PASSWORD_AUTH="no"
                PUBKEY_AUTH="yes"
                ;;
            *)
                print_message "❌ Geçersiz seçim!" "$RED"
                continue
                ;;
        esac
        break
    done
    
    print_message "\n✅ Seçilen yöntem: $AUTH_METHOD ($SECURITY_LEVEL)" "$GREEN"
    
    # Özel SSH config dosyasını oluştur
    sudo tee "$SSH_CUSTOM_CONF" > /dev/null << EOF
# SSH Hardening Configuration
# Generated on $(date)
# DO NOT EDIT THIS FILE MANUALLY

Port $SSH_PORT
Protocol 2
PermitRootLogin no
MaxAuthTries 3
MaxSessions 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 120
StrictModes yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
UsePAM yes
UseDNS no
Compression no
AllowGroups sshusers
PasswordAuthentication $PASSWORD_AUTH
PubkeyAuthentication $PUBKEY_AUTH
ChallengeResponseAuthentication yes
EOF
    
    # AuthenticationMethods ayarı
    case $AUTH_CHOICE in
        1)
            echo "AuthenticationMethods password" | sudo tee -a "$SSH_CUSTOM_CONF" > /dev/null
            ;;
        2)
            echo "AuthenticationMethods keyboard-interactive" | sudo tee -a "$SSH_CUSTOM_CONF" > /dev/null
            ;;
        3)
            echo "AuthenticationMethods publickey" | sudo tee -a "$SSH_CUSTOM_CONF" > /dev/null
            ;;
        4)
            echo "AuthenticationMethods publickey,keyboard-interactive" | sudo tee -a "$SSH_CUSTOM_CONF" > /dev/null
            ;;
    esac
    
    # SSH servisi için gerekli dizinleri oluştur
    print_message "\n🔧 SSH servisi için gerekli dizinler oluşturuluyor..." "$YELLOW"
    sudo mkdir -p /run/sshd
    sudo chmod 0755 /run/sshd
    
    # SSH host key'lerini oluştur (eğer yoksa)
    sudo ssh-keygen -A >/dev/null 2>&1 || true
    
    # SSH config testi
    print_message "🔍 SSH config test ediliyor..." "$YELLOW"
    if sudo sshd -t; then
        print_message "✅ SSH config testi başarılı" "$GREEN"
    else
        print_message "⚠️  SSH config testinde uyarı, ancak devam ediliyor..." "$YELLOW"
        print_message "ℹ️  SSH servisi başlatıldığında otomatik düzeltilecektir" "$BLUE"
    fi
}

# 2FA konfigürasyonu
configure_2fa() {
    if [[ "$AUTH_CHOICE" == "2" || "$AUTH_CHOICE" == "4" ]]; then
        print_message "\n📱 2FA KONFİGÜRASYONU" "$CYAN"
        print_message "─────────────────────" "$BLUE"
        
        sudo apt install -y libpam-google-authenticator qrencode >> "$LOG_FILE" 2>&1
        
        # PAM config - mevcut dosyaya satır ekle (üzerine yazma)
        if ! grep -q "pam_google_authenticator.so" /etc/pam.d/sshd; then
            echo "auth required pam_google_authenticator.so" | sudo tee -a /etc/pam.d/sshd > /dev/null
            print_message "✅ PAM yapılandırıldı" "$GREEN"
        fi
        
        # Kullanıcı için 2FA yapılandırmasını otomatik oluştur
        print_message "🔑 2FA kurulumu yapılıyor..." "$YELLOW"
        
        # Google Authenticator yapılandırmasını otomatik oluştur
        sudo -u "$NEW_USER" bash -c "
            google-authenticator -t -d -f -r 3 -R 30 -w 3 -Q UTF8 << 'EOF'
y
y
y
y
EOF
        " >> "$LOG_FILE" 2>&1
        
        # Kullanıcının Google Authenticator secret'ını al ve göster
        GA_SECRET_FILE="/home/$NEW_USER/.google_authenticator"
        if [[ -f "$GA_SECRET_FILE" ]]; then
            GA_SECRET=$(sudo head -1 "$GA_SECRET_FILE")
            
            print_message "\n🔐 2FA BİLGİLERİ:" "$CYAN"
            print_message "────────────────" "$BLUE"
            print_message "• Secret Key: $GA_SECRET" "$YELLOW"
            print_message "• Bu key'i Google Authenticator uygulamasına manuel ekleyebilirsiniz" "$GREEN"
            print_message "• Her girişte 6 haneli Google Authenticator kodu gerekecek" "$GREEN"
            
            # QR kodu oluştur (qrencode kuruluysa)
            if command -v qrencode &> /dev/null; then
                print_message "\n📱 QR KODU (Google Authenticator ile taratın):" "$BLUE"
                # TOTP URI oluştur
                TOTP_URI="otpauth://totp/$NEW_USER@$SERVER_HOSTNAME?secret=$GA_SECRET&issuer=SSH-Server"
                echo "$TOTP_URI" | qrencode -t UTF8
                print_message "• Veya yukarıdaki QR kodu taratabilirsiniz" "$GREEN"
            fi
            
            # Kurtarma kodlarını göster
            print_message "\n🔑 KURTARMA KODLARI (güvenli bir yere kaydedin!):" "$RED"
            sudo tail -n +2 "$GA_SECRET_FILE" | head -5 | while read code; do
                print_message "   $code" "$YELLOW"
            done
            
            print_message "\n✅ 2FA yapılandırıldı" "$GREEN"
            log_message "2FA yapılandırıldı, secret: ${GA_SECRET:0:10}..."
        else
            print_message "⚠️  2FA dosyası oluşturulamadı!" "$RED"
            print_message "ℹ️  Manuel olarak şu komutu çalıştırın: sudo -u $NEW_USER google-authenticator" "$YELLOW"
        fi
    fi
}

# SSH anahtar yönetimi
manage_ssh_keys() {
    if [[ "$AUTH_CHOICE" == "3" || "$AUTH_CHOICE" == "4" ]]; then
        print_message "\n🔑 SSH ANAHTAR YÖNETİMİ" "$CYAN"
        print_message "───────────────────────" "$BLUE"
        
        # SERVER_HOSTNAME tanımlı değilse, hostname'i al
        if [[ -z "${SERVER_HOSTNAME:-}" ]]; then
            SERVER_HOSTNAME=$(hostname | cut -d'.' -f1 | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
            if [ -z "$SERVER_HOSTNAME" ]; then
                SERVER_HOSTNAME="server"
            fi
        fi
        
        KEY_NAME="$SERVER_HOSTNAME"
        
        print_message "\n📋 İSTEMCİ TARAFINDA YAPILACAKLAR:" "$YELLOW"
        print_message "──────────────────────────────────" "$BLUE"
        echo ""
        print_message "1. İstemci bilgisayarınızda terminal açın" "$GREEN"
        print_message "2. SSH anahtar çifti oluşturun:" "$GREEN"
        print_message "   ssh-keygen -t ed25519 -f ~/.ssh/$KEY_NAME" "$CYAN"
        print_message "   (Parola kısmını boş bırakabilirsiniz - Enter'a basın)" "$YELLOW"
        print_message "3. Dosya izinlerini ayarlayın:" "$GREEN"
        print_message "   chmod 600 ~/.ssh/$KEY_NAME" "$CYAN"
        print_message "4. Public key içeriğini görüntüleyin:" "$GREEN"
        print_message "   cat ~/.ssh/$KEY_NAME.pub" "$CYAN"
        print_message "5. Aşağıdaki satıra public key içeriğini kopyalayıp yapıştırın" "$GREEN"
        echo ""
        print_message "📋 PUBLIC KEY İÇERİĞİNİ AŞAĞIYA YAPIŞTIRIN:" "$YELLOW"
        print_message "(Tüm satırı kopyalayıp yapıştırın, Ctrl+D ile bitirin)" "$BLUE"
        print_message "Örnek: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." "$YELLOW"
        echo ""
        
        # Public key'i oku
        PUBLIC_KEY=$(cat)
        
        if [[ -n "$PUBLIC_KEY" ]]; then
            # .ssh dizinini oluştur
            sudo -u "$NEW_USER" mkdir -p "/home/$NEW_USER/.ssh"
            
            # authorized_keys dosyasına ekle
            echo "$PUBLIC_KEY" | sudo -u "$NEW_USER" tee -a "/home/$NEW_USER/.ssh/authorized_keys" > /dev/null
            
            # İzinleri ayarla
            sudo chmod 700 "/home/$NEW_USER/.ssh"
            sudo chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
            
            print_message "\n✅ Public key başarıyla eklendi" "$GREEN"
            print_message "• Key: ~/.ssh/authorized_keys dosyasına kaydedildi" "$CYAN"
            
            # Bağlantı komutunu göster
            IP_ADDRESS=$(hostname -I | awk '{print $1}')
            print_message "\n🔗 BAĞLANTI KOMUTU:" "$CYAN"
            print_message "ssh -p $SSH_PORT -i ~/.ssh/$KEY_NAME $NEW_USER@$IP_ADDRESS" "$GREEN"
            
            log_message "Public key eklendi: ${PUBLIC_KEY:0:50}..."
        else
            print_message "⚠️  Public key girilmedi!" "$YELLOW"
            print_message "ℹ️  SSH anahtar doğrulama kullanılamayacak." "$BLUE"
            print_message "ℹ️  Daha sonra public key'i şuraya ekleyebilirsiniz:" "$BLUE"
            print_message "    sudo nano /home/$NEW_USER/.ssh/authorized_keys" "$GREEN"
        fi
    fi
}

# Güvenlik duvarı konfigürasyonu
configure_firewall() {
    print_message "\n🔥 GÜVENLİK DUVARI (UFW)" "$CYAN"
    print_message "───────────────────────" "$BLUE"
    
    # UFW zaten aktif mi kontrol et
    if sudo ufw status | grep -q "Status: active"; then
        print_message "ℹ️  UFW zaten aktif" "$YELLOW"
    fi
    
    # UFW'yi sıfırla ve yapılandır
    echo "y" | sudo ufw --force reset >> "$LOG_FILE" 2>&1
    sudo ufw default deny incoming >> "$LOG_FILE" 2>&1
    sudo ufw default allow outgoing >> "$LOG_FILE" 2>&1
    sudo ufw allow "$SSH_PORT/tcp" >> "$LOG_FILE" 2>&1
    echo "y" | sudo ufw enable >> "$LOG_FILE" 2>&1
    
    print_message "✅ Güvenlik duvarı yapılandırıldı" "$GREEN"
    print_message "   • Sadece port $SSH_PORT açık" "$CYAN"
    print_message "   • Gelen trafik varsayılan olarak reddedilir" "$CYAN"
    print_message "   • Giden trafik varsayılan olarak izin verilir" "$CYAN"
}

# Fail2Ban konfigürasyonu
configure_fail2ban() {
    print_message "\n🛡️  FAIL2BAN KONFİGÜRASYONU" "$CYAN"
    print_message "─────────────────────────" "$BLUE"
    
    sudo tee "$FAIL2BAN_CONF" > /dev/null << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
backend = auto
destemail = root@localhost
sender = root@localhost
mta = sendmail
action = %(action_)s
bantime.increment = true
bantime.maxtime = 86400
bantime.factor = 2

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600

[sshd-ddos]
enabled = true
port = $SSH_PORT
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 10
bantime = 86400
EOF
    
    sudo systemctl restart fail2ban >> "$LOG_FILE" 2>&1
    sudo systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    
    print_message "✅ Fail2Ban yapılandırıldı" "$GREEN"
    print_message "   • Maksimum deneme: 5" "$CYAN"
    print_message "   • Ban süresi: 3600 saniye (artan)" "$CYAN"
    print_message "   • Zaman penceresi: 600 saniye" "$CYAN"
    print_message "   • DDOS koruması aktif" "$CYAN"
}

# SSH servisini yeniden başlat
restart_ssh_service() {
    print_message "\n🔄 SSH SERVİSİ YENİDEN BAŞLATILIYOR" "$CYAN"
    print_message "─────────────────────────────────" "$BLUE"
    
    sudo systemctl restart ssh >> "$LOG_FILE" 2>&1
    sudo systemctl enable ssh >> "$LOG_FILE" 2>&1
    
    print_message "✅ SSH servisi yeniden başlatıldı" "$GREEN"
}

# Kurulum özeti
show_summary() {
    print_message "\n🎯 KURULUM ÖZETİ" "$PURPLE"
    print_message "════════════════════════════════════════════════════════════════════════════════" "$PURPLE"
    
    local PUBLIC_IP
    if check_internet; then
        PUBLIC_IP=$(curl -s --connect-timeout 3 icanhazip.com || echo "Bilinmiyor")
    else
        PUBLIC_IP="Bilinmiyor"
    fi
    
    SERVER_HOSTNAME=$(hostname | cut -d'.' -f1 | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
    if [ -z "$SERVER_HOSTNAME" ]; then
        SERVER_HOSTNAME="server"
    fi
    
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    
    echo ""
    print_message "📊 SİSTEM BİLGİLERİ:" "$CYAN"
    print_message "• Sunucu Adı:       $SERVER_HOSTNAME" "$YELLOW"
    print_message "• Kullanıcı:        $NEW_USER" "$YELLOW"
    print_message "• SSH Port:         $SSH_PORT" "$YELLOW"
    print_message "• Yerel IP:         $IP_ADDRESS" "$YELLOW"
    print_message "• Genel IP:         $PUBLIC_IP" "$YELLOW"
    echo ""
    
    print_message "🔐 GÜVENLİK AYARLARI:" "$CYAN"
    print_message "• Kimlik Doğrulama: $AUTH_METHOD" "$YELLOW"
    print_message "• Güvenlik Seviyesi: $SECURITY_LEVEL" "$YELLOW"
    print_message "• Root Girişi:      Devre Dışı" "$YELLOW"
    print_message "• Max Bağlantı:     3 eşzamanlı" "$YELLOW"
    print_message "• Fail2Ban:         Aktif" "$YELLOW"
    print_message "• Güvenlik Duvarı:  Aktif" "$YELLOW"
    echo ""
    
    if [[ "$AUTH_CHOICE" == "3" || "$AUTH_CHOICE" == "4" ]]; then
        print_message "🔑 SSH BAĞLANTI BİLGİLERİ:" "$CYAN"
        print_message "• SSH Komutu:" "$GREEN"
        print_message "  ssh -p $SSH_PORT -i ~/.ssh/$SERVER_HOSTNAME $NEW_USER@$IP_ADDRESS" "$YELLOW"
        
        if [[ "$PUBLIC_IP" != "Bilinmiyor" ]]; then
            print_message "  veya:" "$BLUE"
            print_message "  ssh -p $SSH_PORT -i ~/.ssh/$SERVER_HOSTNAME $NEW_USER@$PUBLIC_IP" "$YELLOW"
        fi
        
        print_message "\n📋 İSTEMCİ KURULUMU:" "$CYAN"
        print_message "1. SSH anahtarını oluştur: ssh-keygen -t ed25519 -f ~/.ssh/$SERVER_HOSTNAME" "$GREEN"
        print_message "2. Private key izinlerini ayarla: chmod 600 ~/.ssh/$SERVER_HOSTNAME" "$GREEN"
        print_message "3. Bağlan: ssh -p $SSH_PORT -i ~/.ssh/$SERVER_HOSTNAME $NEW_USER@$IP_ADDRESS" "$GREEN"
    elif [[ "$AUTH_CHOICE" == "1" || "$AUTH_CHOICE" == "2" ]]; then
        print_message "🔑 BAĞLANTI BİLGİLERİ:" "$CYAN"
        print_message "• SSH Komutu:" "$GREEN"
        print_message "  ssh -p $SSH_PORT $NEW_USER@$IP_ADDRESS" "$YELLOW"
        
        if [[ "$PUBLIC_IP" != "Bilinmiyor" ]]; then
            print_message "  veya:" "$BLUE"
            print_message "  ssh -p $SSH_PORT $NEW_USER@$PUBLIC_IP" "$YELLOW"
        fi
    fi
    
    if [[ "$AUTH_CHOICE" == "2" || "$AUTH_CHOICE" == "4" ]]; then
        print_message "\n📱 2FA BİLGİLERİ:" "$CYAN"
        print_message "• Her girişte Google Authenticator kodu gerekecek" "$YELLOW"
        print_message "• 2FA kodları 30 saniyede bir değişir" "$YELLOW"
        print_message "• Kurtarma kodlarını saklayın" "$YELLOW"
    fi
    
    echo ""
    print_message "✅ AYARLAR KALICIDIR" "$GREEN"
    print_message "📋 Log dosyası: $LOG_FILE" "$BLUE"
    
    # Özet dosyasını kullanıcı dizinine kaydet
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
• Fail2Ban:         Aktif (5 deneme)
• Güvenlik Duvarı:  Aktif

$(if [[ "$AUTH_CHOICE" == "3" || "$AUTH_CHOICE" == "4" ]]; then
echo "SSH ANAHTAR BAĞLANTISI:"
echo "ssh -p $SSH_PORT -i ~/.ssh/$SERVER_HOSTNAME $NEW_USER@$IP_ADDRESS"
if [[ "$PUBLIC_IP" != "Bilinmiyor" ]]; then
echo "veya: ssh -p $SSH_PORT -i ~/.ssh/$SERVER_HOSTNAME $NEW_USER@$PUBLIC_IP"
fi
echo ""
elif [[ "$AUTH_CHOICE" == "1" || "$AUTH_CHOICE" == "2" ]]; then
echo "PAROLA BAĞLANTISI:"
echo "ssh -p $SSH_PORT $NEW_USER@$IP_ADDRESS"
if [[ "$PUBLIC_IP" != "Bilinmiyor" ]; then
echo "veya: ssh -p $SSH_PORT $NEW_USER@$PUBLIC_IP"
fi
echo ""
fi)

$(if [[ "$AUTH_CHOICE" == "2" || "$AUTH_CHOICE" == "4" ]]; then
echo "2FA NOTLARI:"
echo "- Her girişte Google Authenticator kodu gerekecek"
echo "- 2FA kodları 30 saniyede bir değişir"
echo "- Kurtarma kodlarını saklayın"
echo ""
fi)

KURULUM TARİHİ: $(date)
LOG DOSYASI: $LOG_FILE
EOF
    
    sudo chown "$NEW_USER:$NEW_USER" "$SUMMARY_FILE"
    sudo chmod 644 "$SUMMARY_FILE"
    
    print_message "\n📄 Özet dosyası: $SUMMARY_FILE" "$BLUE"
}

# Ana kurulum fonksiyonu
main() {
    clear
    print_message "\n🎯 ============================================" "$PURPLE"
    print_message "     Ubuntu Server SSH Kurulum Scripti" "$PURPLE"
    print_message "     Geliştirilmiş ve Güvenli Versiyon" "$PURPLE"
    print_message "============================================\n" "$PURPLE"
    
    # Log dosyasını başlat
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    log_message "Script başlatıldı"
    
    # Başlangıç kontrolleri
    check_root
    check_internet
    
    # Sistem bilgilerini göster
    show_system_info
    
    # Root parola yönetimi
    manage_root_password
    
    # Kullanıcı oluşturma
    create_user
    
    # SSH port ayarı
    configure_ssh_port
    
    # Sistem güncellemeleri
    update_system
    
    # Güvenlik güncellemeleri
    configure_security_updates
    
    # Paket kurulumu
    install_packages
    
    # SSH konfigürasyonu
    configure_ssh
    
    # 2FA konfigürasyonu
    configure_2fa
    
    # SSH anahtar yönetimi
    manage_ssh_keys
    
    # Güvenlik duvarı
    configure_firewall
    
    # Fail2Ban
    configure_fail2ban
    
    # SSH servisini yeniden başlat
    restart_ssh_service
    
    # Kurulum özeti
    show_summary
    
    print_message "\n🎉 KURULUM TAMAMLANDI!" "$GREEN"
    print_message "════════════════════════════════════════════════════════════════════════════════" "$PURPLE"
    
    # Log dosyasını kapat
    log_message "Kurulum tamamlandı"
}

# =============================================================================
# ANA PROGRAM
# =============================================================================

# Ana fonksiyonu çalıştır
main "$@"
