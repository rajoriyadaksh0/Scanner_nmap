import nmap
import argparse
import sys
from datetime import datetime

# ---- Defining Arguments -----
BANNER = r"""
  ██████  ▄████▄   ▄▄▄       ███▄    █  ███▄    █ ▓█████  ██▀███  
▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █  ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄  
▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░▒██░   ▓██░░▒████▒░██▓ ▒██▒
▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
░  ░  ░  ░          ░   ▒      ░   ░ ░    ░   ░ ░    ░     ░░   ░ 
      ░  ░ ░            ░  ░         ░          ░    ░  ░   ░     
         ░                                                              
"""
print(BANNER)
parser=argparse.ArgumentParser()

parser.add_argument("target",help="Target to Scan (e.g. '127.0.0.1', 'example.com')")
parser.add_argument("-sS","--syn-scan",action="store_true",help="TCP SYN Scan")
parser.add_argument("-sV","--version-scan",action="store_true",help="TCP version Scan")
parser.add_argument("-sC","--script-scan",action="store_true",help="Default Script Scan")
parser.add_argument("-sU","--udp-scan",action="store_true",help="UDP Scan")
parser.add_argument("-oN","--output-normal",help="Store output as text file (e.g. 'scan.txt')")
parser.add_argument("-Pn",action="store_true",help="Skip Ping")
parser.add_argument("-p","--port",default="1-1024",help="Mention the port or default (1-1024) will be used")

args=parser.parse_args()



#---- Scan Execution ----

try:
    nm=nmap.PortScanner()
except nmap.nmap.PortScannerError:
    print(f"[-] No Nmap found, Please Install Nmap")
    sys.exit(1)

args_string=""
if args.syn_scan:
    args_string += "-sS"
if args.udp_scan:
    args_string += "-sU"
if args.script_scan:
    args_string += "-sC"
if args.version_scan:
    args_string += "-sV"

print(f"[+] Starting Scan on {args.target} (Ports: 1-1024)")
print(f"[+] Arguments {args_string}")
start_time=datetime.now()

try:
    nm.scan(args.target,args.port,arguments=args_string)
except nmap.nmap.PortScannerError as e:
    print(f"[-] Unexpected Error Occured: {e}")
    sys.exit(1)

# ----- Report Time -----
report=[]
for host in nm.all_hosts():
    if nm[host].state() == 'down':
        report.append(f"Host: {host} is down.")
        continue
            
    report.append("=" * 40)
    report.append(f"Host: {host} ({nm[host].hostname()})")
    report.append(f"State: {nm[host].state().upper()}")
    report.append("=" * 40)

    for proto in nm[host].all_protocols():
        report.append(f"Protocol: {proto}")
        report.append(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'VERSION'}")

        ports=nm[host][proto].keys()
        for port in ports:
            port_info=nm[host][proto][port]
            state=port_info['state']
            service=port_info['name']
            version=port_info['version']

            report.append(f"{port:<10} {state:<10} {service:<20} {version}")
            # print(f"{port:<10} {state:<10} {service:<20} {version}")

            if args.script_scan and 'script' in port_info:
                for script_id, output in port_info['script'].items():
                    report.append(f"    Script: {script_id}")
                    for line in output.split('\n'):
                        report.append(f"      {line}")
    report.append("=" * 40)

end_time=datetime.now()
duration=end_time - start_time
report.append(f"Scan finished with duration {duration.total_seconds():.2f}")

final_report='\n'.join(report)

# ---- Saving Report -----
if args.output_normal:
    try:
        with open(args.output_normal,'w') as f:
            f.write(final_report)
        print(f"[+] final report saved to {args.output_normal}")

    except IOError as e:
        print(f"[-] Error Saving Report: {e}")

else:
    print(final_report)


    


    
    







