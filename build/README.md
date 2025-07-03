## Building chainwalk
> Recommended to use Ubuntu 22.04 LTS Server on VirtualBox, please set port forwarding for ports mentioned

This project simulates a vulnerable Langchain-ChatChat deployment using Ollama as the LLM backend. It is intended for CTF labs and controlled security testing environments.

### Assumed Directory

The root path for setup is:

```
/home/vboxuser/chainwalk
```

### Installation

Navigate to the `build` directory:

```bash
cd /home/vboxuser/chainwalk/build
chmod +x build.sh
sudo ./build.sh
```

### Script Actions

* Updates system packages and installs dependencies
* Uses Ollama as backend instead of Xinference
* Loads `qwen2.5:0.5b` as the chat model
* Uses `quentinz/bge-large-zh-vh1.5:latest` as the embedding model
* Installs a vulnerable version of Langchain-ChatChat
* Creates a systemd service to run ChatChat at startup
* Sets up SSH keys
* Applies firewall rules to allow ChatChat API, Web UI, and a dedicated exploitation port
* Disables shell history
* Changes the system hostname

After running the script, initialization may take time. If the screen appears stuck, press Enter to continue (this typically occurs after knowledge base setup).

### Flag Setup

The `setflag.py` script sets the flag for the challenge.

### Default Credentials (Testing Only)

```
Username: vboxuser
Password: changeme
```

Change these in real environments.
