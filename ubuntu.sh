#!/usr/bin/env bash
set -Eeuo pipefail

# ======================
# == GLOBAL SETTINGS ==
# ======================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
SSH_HARDENING_FILE="$SSH_CONFIG_DIR/99-hardening.conf"
SSH_PORT_DEFAULT=2222
SSH_GROUP="sshusers"

trap 'echo -e "${RED}❌ Hata oluştu. Script durduruldu.${NC}"' ERR

# ======================
# == FUNCTIONS        ==
# ======================

print() {
  echo -e "${BLUE}▶${NC} $1"
}

success() {
  echo -e "${GREEN}✔${NC} $1"
}

warn() {
  echo -e "${YELLOW}⚠${NC} $1"
}

# ======================
# == PRIVILEGE CHECK ==
# ======================

if [[ "$EUID" -ne 0 ]]; then
  warn "Script root olarak çalışmıyor. Root yetkileri gerektiren adımlar için sudo kullanılacak."
  SUDO="sudo"
else
  SUDO=""
fi

check_os
check_internet() {
  print "İnternet bağlantısı kontrol ediliyor"
  if ! curl -s --head https://deb.debian.org >/dev/null; then
    echo -e "${RED}İnternet erişimi yok.${NC}"
    exit 1
  fi
  success "İnternet bağlantısı OK"
}

ask() {
  read -rp "$1" REPLY
}

ask_yes_no() {
  while true; do
    read -rp "$1 (y/n): " yn
    case $yn in
      [Yy]*) return 0;;
      [Nn]*) return 1;;
    esac
  done
}

# ======================
# == PRECHECKS       ==
# ======================

require_root
check_os
check_internet

# ======================
# == USER SETUP      ==
# ======================

print "Yeni kullanıcı oluşturma"
read -rp "Kullanıcı adı: " USERNAME

if id "$USERNAME" &>/dev/null; then
  success "Kullanıcı zaten mevcut"
else
  adduser "$USERNAME"
fi

print "SSH kullanıcı grubu kontrol ediliyor"
getent group "$SSH_GROUP" >/dev/null || groupadd "$SSH_GROUP"
usermod -aG sudo,"SSH_GROUP" "$USERNAME"

# ======================
# == ROOT PASSWORD   ==
# ======================

if ask_yes_no "Root parolasını değiştirmek ister misiniz? (önerilir)"; then
  passwd root
fi

# ======================
# == SSH KEY SETUP   ==
# ======================

print "Public SSH key girilmesi"
echo "Lütfen istemci tarafında şu komutu çalıştırın:" 
echo "  ssh-keygen -t ed25519"
echo "Sonra .pub dosyasının içeriğini aşağıya yapıştırın:"

auth_dir="/home/$USERNAME/.ssh"
mkdir -p "$auth_dir"
chmod 700 "$auth_dir"

read -rp "SSH Public Key: " PUBKEY
echo "$PUBKEY" > "$auth_dir/authorized_keys"
chmod 600 "$auth_dir/authorized_keys"
chown -R "$USERNAME:$USERNAME" "$auth_dir"

success "SSH key eklendi"

# ======================
# == SSH HARDENING   ==
# ======================

print "SSH port ayarı"
read -rp "SSH port (1024-65535) [default: $SSH_PORT_DEFAULT]: " SSH_PORT
SSH_PORT=${SSH_PORT:-$SSH_PORT_DEFAULT}

mkdir -p "$SSH_CONFIG_DIR"

cat > "$SSH_HARDENING_FILE" <<EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowGroups $SSH_GROUP
X11Forwarding no
MaxAuthTries 3
EOF

sshd -t
systemctl restart ssh
success "SSH hardening tamamlandı"

# ======================
# == 2FA (OPTIONAL)  ==
# ======================

if ask_yes_no "Google Authenticator (2FA) kurulsun mu?"; then
  apt install -y libpam-google-authenticator
  echo "auth required pam_google_authenticator.so nullok" >> /etc/pam.d/sshd
  sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
  systemctl restart ssh
  warn "2FA aktif. Kullanıcılar google-authenticator çalıştırmalı"
fi

# ======================
# == FIREWALL       ==
# ======================

print "UFW yapılandırılıyor"
apt install -y ufw
ufw allow "$SSH_PORT"/tcp
ufw --force enable
success "Firewall aktif"

# ======================
# == FAIL2BAN       ==
# ======================

print "Fail2Ban kuruluyor"
apt install -y fail2ban

cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
port = $SSH_PORT
backend = systemd
bantime = 1h
bantime.increment = true
maxretry = 3
EOF

systemctl restart fail2ban
success "Fail2Ban aktif"

# ======================
# == SUMMARY        ==
# ======================

echo -e "\n${GREEN}Kurulum tamamlandı!${NC}"
echo "Kullanıcı: $USERNAME"
echo "SSH Port: $SSH_PORT"
echo "Root SSH: Kapalı"
echo "Password Auth: Kapalı"
