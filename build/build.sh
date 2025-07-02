# Machine: CHAINWALK (CVE-2025-6855)
# Author: dutta_ayush@srmap.edu.in

# Installing packages
apt update
apt install -y net-tools open-vm-tools openssh-server python3 python3-pip curl

# Installing ollama backend
curl -fsSL https://ollama.com/install.sh | sh
# Installing models 
ollama pull qwen2.5:0.5b 
ollama pull quentinz/bge-large-zh-v1.5:latest
ollama serve
# Installing chatchat client
pip install -r chatchat_requirements.txt
# Initialising
chatchat kb -r 
# Launch app! but in background
chatchat start -a &

# Upload the flag
python3 setflag.py

# Configuring SSH
ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N "" -q
cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# Configuring services
systemctl daemon-reload
systemctl enable ssh
systemctl restart ssh

# Configuring Firewall
sed -i 's/IPV6=yes/IPV6=no/g' /etc/default/ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow 7861/tcp
ufw allow 8501
ufw enable
ufw status verbose

# Disabling history
ln -sf /dev/null /root/.bash_history

# Configuring passwords
echo "root:carpet-petrol-toddy-parboil" | chpasswd

# Configuring hostname
hostnamectl set-hostname chainwalk
cat << EOF > /etc/hosts
127.0.0.1 localhost
127.0.0.1 chainwalk
EOF

# Cleaning up
rm -rf /root/build.sh
rm -rf /root/.cache
find /var/log -type f -exec sh -c "cat /dev/null > {}" \;
