#!/usr/bin/env bash
set -Eeuo pipefail

# ==================================================
# Ubuntu & Debian Interactive SSH Hardening Script
# USER-FIRST • INTERACTIVE • BEST PRACTICES
# ==================================================

# ======================
# == COLORS / UI      ==
# ======================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print()   { echo -e "${BLUE}▶${NC} $1"; }
success() { echo -e "${GREEN}✔${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
error()   { echo -e "${RED}✖${NC} $1"; }

trap 'error "Beklenmeyen bir hata oluştu. Script durduruldu."' ERR

# ======================
# == PRIVILEGE MODEL ==
# ======================

if [[ "$EUID" -ne 0 ]]; then
  warn "Script root olarak çalışmıyor. Gerekli adımlar sudo ile yürütülecek."
  SUDO="sudo"
else
  SUDO=""
fi

# ======================
# == PRECHECKS       ==
# ======================

command -v apt >/dev/null || { error "Sadece Ubuntu / Debian desteklenir"; exit 1; }

print "İnternet bağlantısı kontrol ediliyor"
$SUDO curl -fsSL https://deb.debian.org >/dev/null || { error "İnternet yok"; exit 1; }
success "İnternet bağlantısı OK"

# ======================
# == SYSTEM INFO    ==
# ======================

print "Mevcut sistem bilgileri"
echo "OS        : $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "Hostname  : $(hostname)"
echo "Kullanıcı : $(whoami)"

# ======================
# == USER MANAGEMENT ==
# ======================

print "\n👥 KULLANICI YÖNETİMİ"
print "────────────────────"

echo "1) Yeni bir kullanıcı hesabı oluştur (önerilir)"
echo "2) Mevcut kullanıcı hesabı ile devam et"

while true; do
  read -rp "Seçiminiz (1/2): " USER_CHOICE
  case "$USER_CHOICE" in
    1)
      read -rp "Oluşturulacak kullanıcı adı: " USERNAME
      if id "$USERNAME" &>/dev/null; then
        warn "Kullanıcı zaten mevcut, bu kullanıcı kullanılacak"
      else
        $SUDO adduser "$USERNAME"
      fi
      break
      ;;
    2)
      USERNAME="$(whoami)"
      success "Mevcut kullanıcı ile devam ediliyor: $USERNAME"
      break
      ;;
    *) warn "Geçersiz seçim, lütfen 1 veya 2 girin";;
  esac
done

# Ortak grup ayarları
$SUDO groupadd -f sshusers
$SUDO usermod -aG sudo,sshusers "$USERNAME"

# ======================
# == SSH KEY SETUP  ==
# ======================

read -rp "SSH key tabanlı giriş yapılandırılsın mı? (önerilir) [y/n]: " USE_KEYS
if [[ "$USE_KEYS" =~ ^[Yy]$ ]]; then
  print "SSH Public Key kurulumu"
  echo "Client tarafında çalıştırın: ssh-keygen -t ed25519"
  read -rp "Public key (.pub içeriği): " PUBKEY

  SSH_DIR="/home/$USERNAME/.ssh"
  $SUDO mkdir -p "$SSH_DIR"
  echo "$PUBKEY" | $SUDO tee "$SSH_DIR/authorized_keys" >/dev/null

  $SUDO chmod 700 "$SSH_DIR"
  $SUDO chmod 600 "$SSH_DIR/authorized_keys"
  $SUDO chown -R "$USERNAME:$USERNAME" "$SSH_DIR"

  SSH_AUTH="key"
  success "SSH key eklendi"
else
  SSH_AUTH="password"
  warn "SSH parola tabanlı giriş aktif olacak"
fi

# ======================
# == ROOT PASSWORD ==
# ======================

read -rp "Root parolasını değiştirmek ister misiniz? (önerilir) [y/n]: " CHANGE_ROOT
[[ "$CHANGE_ROOT" =~ ^[Yy]$ ]] && $SUDO passwd root

# ======================
# == SSH PORT       ==
# ======================

while true; do
  read -rp "SSH port (1024-65535) [2222]: " SSH_PORT
  SSH_PORT=${SSH_PORT:-2222}
  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1024 && SSH_PORT <= 65535 )) && break
  warn "Geçersiz port numarası"
done

# ======================
# == SSH HARDENING  ==
# ======================

print "SSH yapılandırılıyor"
$SUDO mkdir -p /etc/ssh/sshd_config.d

$SUDO tee /etc/ssh/sshd_config.d/99-hardening.conf >/dev/null <<EOF
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication $( [[ "$SSH_AUTH" == "password" ]] && echo yes || echo no )
AllowGroups sshusers
X11Forwarding no
MaxAuthTries 3
EOF

print "SSH config test ediliyor"
$SUDO sshd -t
$SUDO systemctl restart ssh
success "SSH yeniden başlatıldı"

# ======================
# == OPTIONAL 2FA   ==
# ======================

read -rp "2FA (Google Authenticator) kurulsun mu? [y/n]: " ENABLE_2FA
if [[ "$ENABLE_2FA" =~ ^[Yy]$ ]]; then
  $SUDO apt install -y libpam-google-authenticator
  grep -q pam_google_authenticator /etc/pam.d/sshd || \
    echo "auth required pam_google_authenticator.so nullok" | $SUDO tee -a /etc/pam.d/sshd
  $SUDO sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
  $SUDO systemctl restart ssh
  warn "Kullanıcılar için: google-authenticator çalıştırılmalı"
fi

# ======================
# == FIREWALL (UFW) ==
# ======================

$SUDO apt install -y ufw
$SUDO ufw allow "$SSH_PORT"/tcp
$SUDO ufw --force enable
success "UFW aktif"

# ======================
# == FAIL2BAN       ==
# ======================

$SUDO apt install -y fail2ban

$SUDO tee /etc/fail2ban/jail.d/sshd.local >/dev/null <<EOF
[sshd]
enabled = true
port = $SSH_PORT
backend = systemd
bantime = 1h
bantime.increment = true
maxretry = 3
EOF

$SUDO systemctl restart fail2ban
success "Fail2Ban aktif"

# ======================
# == SUMMARY        ==
# ======================

echo -e "\n${GREEN}Kurulum tamamlandı${NC}"
echo "Kullanıcı        : $USERNAME"
echo "SSH Port         : $SSH_PORT"
echo "Kimlik Doğrulama : $SSH_AUTH"
echo "Root SSH         : Kapalı"
