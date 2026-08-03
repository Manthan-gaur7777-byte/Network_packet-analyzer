from scapy.all import *
from collections import Counter
import ipaddress
import socket
print("\n")
print("="*70)
print("      NETWORK INTRUSION DETECTION SYSTEM (NIDS)")
print("                     VERSION 1.0")
print("="*70)
print("\nInitializing IDS Engine....................[SUCCESS]")
print("Loading Detection Modules...................[SUCCESS]")
print("Loading Packet Analysis Module..............[SUCCESS]")
print("Loading Traffic Analysis Module.............[SUCCESS]")
print("Loading Risk Analysis Module................[SUCCESS]")
print("Loading Security Modules....................[SUCCESS]")
print("Loading Failed Log-in Modules....................[SUCCESS]")
print("Loading Alert Modules....................[SUCCESS]")
print("\nAvailable Detection Modules :")
print("-"*70)
print("[+] High Request Detection")
print("[+] Packet Spike Detection")
print("[+] Port Scan Detection")
print("[+] External IP Classification")
print("[+] Risk Analysis")
print("[+] FAILED LOGIN DETECTION")
print("[+] ALERT SYSTEM")
print("-"*70)
print("\nStarting Network Analysis...")
print("="*70)
print("\nLoading PCAP File......")

packets = rdpcap("sample2.pcapng") #enter the file name here
print("[SUCCESS] PCAP File Loaded Successfully.")
print("Total Packets Found :",len(packets))
source_ips = Counter()
destination_ips = Counter()
ports = Counter()
protocols = Counter()
packet_sizes = []
all_packets = []
ip_to_ports={}
ip_to_packets={}
port_scan_ips=[]
risk_scores={}
ip_to_time={}
time_taken={}
packets_per_second={}
low_traffic_ips=[]
medium_traffic_ips=[]
high_traffic_ips=[]
critical_traffic_ips=[]
packet_spike_ips=[]
private_ips=[]
unknown_public_ips=[]
unknown_ips=[]
known_public_ips=[]
ip_organization={}
known_organizations={     #we can add more if we need
    "GOOGLE":[    
        "google",
        "1e100.net"
        ],
    "AWS":[
        "amazonaws",
        "cloudfront"
        ],
    "CLOUDFLARE":[
        "cloudflare"
        ],
    "AKAMAI":[
        "akamai"
        ],
    "MICROSOFT":[
        "microsoft"
        ],
    "GITHUB":[
        "github"
        ],
    "NETFLIX":[
        "netflix"
        ],
    "OPENAI":[
        "openai"
        ]
}
failed_login_ips=[]
suspicious_port_scan_ips=[]
login_ports={
                    #for now i have included only some of the ports
    # for FTP
    20,
    21,
    # for SSH
    22,
    # for TELNET
    23,
    # for SMB
    445,
    # for MYSQL
    3306,
    # for MSSQL
    1433,
    # for PostgreSQL
    5432,
    # for Oracle
    1521,
    # for RDP
    3389
}
ip_has_login_ports={}
low_alert_ips=[]
medium_alert_ips=[]
high_alert_ips=[]
critical_alert_ips=[]
# packet info and intro
for packet in packets:
    packet_info = {}
    size = len(packet)
    packet_sizes.append(size)
    packet_info["size"] = size
    packet_info["timestamp"]=packet.time
    if IP in packet:
        src_ip = packet[IP].src
        if src_ip not in ip_to_time:
            ip_to_time[src_ip]=[]
        if src_ip not in ip_has_login_ports:
            ip_has_login_ports[src_ip]=False
        ip_to_time[src_ip].append(packet.time)
        dst_ip = packet[IP].dst
        packet_info["source_ip"] = src_ip
        packet_info["destination_ip"] = dst_ip
        ip_to_packets[src_ip]=ip_to_packets.get(src_ip,0)+1
        if src_ip not in ip_to_ports:
            ip_to_ports[src_ip]=set()
        if TCP in packet:
            ip_to_ports[src_ip].add(packet[TCP].dport)
        elif UDP in packet:
            ip_to_ports[src_ip].add(packet[UDP].dport)
        source_ips[src_ip] += 1
        destination_ips[dst_ip] += 1
    else:
        packet_info["source_ip"] = "Unknown"
        packet_info["destination_ip"] = "Unknown"
    if TCP in packet:
        packet_info["protocol"] = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if dport in login_ports:
            ip_has_login_ports[src_ip]=True
        packet_info["source_port"] = sport
        packet_info["destination_port"] = dport
        ports[sport] += 1
        ports[dport] += 1
        protocols["TCP"] += 1
    elif UDP in packet:
        packet_info["protocol"] = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        if dport in login_ports:
            ip_has_login_ports[src_ip]=True
        packet_info["source_port"] = sport
        packet_info["destination_port"] = dport
        ports[sport] += 1
        ports[dport] += 1
        protocols["UDP"] += 1
    elif ICMP in packet:
        packet_info["protocol"] = "ICMP"
        packet_info["source_port"] = "N/A"
        packet_info["destination_port"] = "N/A"
        protocols["ICMP"] += 1
    else:
        packet_info["protocol"] = "OTHER"
        packet_info["source_port"] = "N/A"
        packet_info["destination_port"] = "N/A"
        protocols["OTHER"] += 1
    all_packets.append(packet_info)    
    #early stage analysis
print("\n")
print("="*60)
print("NETWORK TRAFFIC SUMMARY")
print("="*60)
print("\nTotal Packets :",len(packets))
print("\nLargest Packet :",max(packet_sizes),"Bytes")
print("Smallest Packet :",min(packet_sizes),"Bytes")
print("Average Packet Size :",
      round(sum(packet_sizes)/len(packet_sizes),2),"Bytes")
print("\n")
print("="*60)
print("PROTOCOL STATISTICS")
print("="*60)
for protocol,count in protocols.items():
    print(protocol,"----->",count)
print("\n")
print("="*60)
print("TOP 10 SOURCE IPS")
print("="*60)
for ip,count in source_ips.most_common(10):
    print(ip,"----->",count)
print("\n")
print("="*60)
print("TOP 10 DESTINATION IPS")
print("="*60)
for ip,count in destination_ips.most_common(10):
    print(ip,"----->",count)
print("\n")
print("="*60)
print("TOP 10 PORTS")
print("="*60)
for port,count in ports.most_common(10):
    print(port,"----->",count)
print("\n")
print("="*60)
print("FIRST 5 STORED PACKETS")
print("="*60)
for i in range(min(5,len(all_packets))):
    print("\nPacket :",i+1)
    print("Source IP :",all_packets[i]["source_ip"])
    print("Destination IP :",all_packets[i]["destination_ip"])
    print("Protocol :",all_packets[i]["protocol"])
    print("Size :",all_packets[i]["size"])
    print("Source Port :",all_packets[i]["source_port"])
    print("Destination Port :",all_packets[i]["destination_port"])
    print("Timestamp :",all_packets[i]["timestamp"])
print("-"*40)
print("\n")
print("="*60)
print("IP ANALYSIS")
print("="*60)
for ip in ip_to_packets:
    print("\nIP Address :",ip)
    print("Total Packets :",
          ip_to_packets[ip])
    print("Unique Ports Used :",
          len(ip_to_ports[ip]))
    print("Ports Used :")
    print(ip_to_ports[ip])
    print("-"*40)    
most_active_ip=max(ip_to_packets,key=ip_to_packets.get)
print("\n")
print("="*60)
print("MOST ACTIVE IP")
print("="*60)
print(most_active_ip)
print("Packets :",
      ip_to_packets[most_active_ip])
print("\n")
#risk analysis
print("="*60)
print("RISK ANALYSIS")
print("="*60)
for ip in ip_to_packets:
    score=0
    packets_count=ip_to_packets[ip]
    unique_ports=len(ip_to_ports[ip])
    if packets_count>1000:
        score+=10
    if packets_count>3000:
        score+=20
    if unique_ports>5:
        score+=20
    if unique_ports>15:
        score+=30
    risk_scores[ip]=score
for ip in risk_scores:
    print("\nIP ADDRESS :",ip)
    packets_local=ip_to_packets[ip]
    unique_ports=len(ip_to_ports[ip])
    print("Packets :",packets_local)
    print("Unique Ports :",unique_ports)
    print("Risk Score :",risk_scores[ip])
    if risk_scores[ip]<20:
        level="LOW"
    elif risk_scores[ip]<50:
        level="MEDIUM"
    elif risk_scores[ip]<80:
        level="HIGH"
    else:
        level="CRITICAL"
    print("Risk Level :",level)
    print("-"*40)
print("\n")
print("="*60)
print("TOP 5 MOST DANGEROUS IPS")
print("="*60)
dangerous_ips=sorted(risk_scores.items(),key=lambda x:x[1],reverse=True)
for ip,score in dangerous_ips[:5]:
    print("\nIP :",ip)
    print("Risk Score :",score)
        #cal packet size(starting of time )
for time_ip in ip_to_time:
    first_time=ip_to_time[time_ip][0]
    last_time=ip_to_time[time_ip][-1]
    total_time=last_time-first_time
    if total_time==0:
        total_time=1
    time_taken[time_ip]=total_time
    packets_per_second[time_ip]=(ip_to_packets[time_ip]/total_time)
    print("\nFor IP :",time_ip)
    print("First Time Stamp :")
    print(ip_to_time[time_ip][0])
    print("Last Time Stamp :")
    print(ip_to_time[time_ip][-1])
    print("Total Time :")
    print(round(time_taken[time_ip],2))
    print("Packets Per Second :")
    print(round(packets_per_second[time_ip],2))
    print("Total Packets :")
    print(ip_to_packets[time_ip])
    print("-"*40)
for request_ip in packets_per_second:
    current_pps=packets_per_second[request_ip]
    if 50<=current_pps<100:
        low_traffic_ips.append(request_ip)
    elif 100<=current_pps<200:
        medium_traffic_ips.append(request_ip)
    elif 200<=current_pps<500:
        high_traffic_ips.append(request_ip)
    elif current_pps>=500:
        critical_traffic_ips.append(request_ip)
for ip in ip_to_ports:
    unique_ports=len(ip_to_ports[ip])
    current_pps=packets_per_second[ip]
    if(
        unique_ports>20
        and
        time_taken[ip]<5
        and
        current_pps>20
        ):
        suspicious_port_scan_ips.append(ip)
    elif(
        unique_ports>20
        and
        time_taken[ip]<5
        ):
        port_scan_ips.append(ip)
        # port scan 
print("\n")
print("="*60)
print("PORT SCAN DETECTION")
print("="*60)
print("\nMEDIUM ALERTS")
print("-"*40)
if len(port_scan_ips)==0:
    print("No Medium Port Scan Alerts.")
else:
    for ip in port_scan_ips:
        print("\nIP :",ip)
        print("Packets :",
              ip_to_packets[ip])
        print("Unique Ports :",
              len(ip_to_ports[ip]))
        print("Packets/sec :",
              round(
                    packets_per_second[ip],
                    2))
        print("Time Taken :",
              round(
                    time_taken[ip],
                    2),
              "seconds")
        print("Alert Level : MEDIUM")
        print("Reason :")
        print("Multiple ports were accessed "
              "within a short time period.")
        print("-"*40)
print("\nHIGH ALERTS")
print("-"*40)
if len(suspicious_port_scan_ips)==0:
    print("No High Port Scan Alerts.")
else:
    for ip in suspicious_port_scan_ips:
        print("\nWARNING !!!")
        print("IP :",ip)
        print("Packets :",
              ip_to_packets[ip])
        print("Unique Ports :",
              len(ip_to_ports[ip]))
        print("Packets/sec :",round(  packets_per_second[ip],  2))

        print("Time Taken :",round( time_taken[ip],2),"seconds")
        print("Alert Level : HIGH")
        print("Reason :")
        print("Possible aggressive "
              "port scan detected.")
        print("-"*40)
    #  trafic detection   
print("\n")
print("="*60)
print("HIGH REQUEST DETECTION")
print("="*60)
print("\nLOW TRAFFIC ALERTS")
print("-"*40)
if len(low_traffic_ips)==0:
    print("No Low Traffic Alerts.")
else:
    for request_ip in low_traffic_ips:
        print("\nIP :",request_ip)
        print("Packets :",
              ip_to_packets[request_ip])
        print("Packets/sec :",
              round(
              packets_per_second[request_ip],
              2))
        print("Time Taken :",
              round(
              time_taken[request_ip],
              2),
              "seconds")
        print("Traffic Level : LOW")
        print("Reason : Generated moderate traffic.")
        print("-"*40)
print("\nMEDIUM TRAFFIC ALERTS")
print("-"*40)
if len(medium_traffic_ips)==0:
    print("No Medium Traffic Alerts.")
else:
    for request_ip in medium_traffic_ips:
        print("\nIP :",request_ip)
        print("Packets :",
              ip_to_packets[request_ip])
        print("Packets/sec :",
              round(
              packets_per_second[request_ip],
              2))
        print("Time Taken :",
              round(
              time_taken[request_ip],
              2),
              "seconds")
        print("Traffic Level : MEDIUM")
        print("Reason : Generated unusually high traffic.")
        print("-"*40)
print("\nHIGH TRAFFIC ALERTS")
print("-"*40)
if len(high_traffic_ips)==0:
    print("No High Traffic Alerts.")
else:
    for request_ip in high_traffic_ips:
        print("\nIP :",request_ip)
        print("Packets :",
              ip_to_packets[request_ip])
        print("Packets/sec :",
              round(
              packets_per_second[request_ip],
              2))
        print("Time Taken :",
              round(
              time_taken[request_ip],
              2),
              "seconds")
        print("Traffic Level : HIGH")
        print("Reason : Generated very high traffic.")
        print("-"*40)
print("\nCRITICAL TRAFFIC ALERTS")
print("-"*40)
if len(critical_traffic_ips)==0:
    print("No Critical Traffic Alerts.")
else:
    for request_ip in critical_traffic_ips:
        print("\nIP :",request_ip)
        print("Packets :",
              ip_to_packets[request_ip])
        print("Packets/sec :",
              round(
              packets_per_second[request_ip],
              2))
        print("Time Taken :",
              round(
              time_taken[request_ip],
              2),
              "seconds")
        print("Traffic Level : CRITICAL")
        print("Reason : Possible Packet Spike Detected.")
        print("-"*40)
# packet_spike detection        
for spike_ip in packets_per_second:
    if packets_per_second[spike_ip]>=500:
        packet_spike_ips.append(spike_ip)        
print("\n")
print("="*60)
print("PACKET SPIKE DETECTION")
print("="*60)
if len(packet_spike_ips)==0:
    print("\nNO PACKET SPIKES DETECTED.")
else:
    for spike_ip in packet_spike_ips:
        print("\nWARNING !!!")
        print("IP :",spike_ip)
        print("Packets :", ip_to_packets[spike_ip])
        print("Packets/sec :",round(packets_per_second[spike_ip],2) )
        print("Time Taken :",round(time_taken[spike_ip],2),"seconds")
        print("Reason :")
        print("Sudden spike in packet volume detected.")
        print("-"*40)   
    #for failed login attempts
for ip in ip_to_packets:
    if( ip_has_login_ports[ip] and packets_per_second[ip]>20 and time_taken[ip]<10 ):
        failed_login_ips.append(ip)
    #ip classification so that atlest our local ip is considered
print("\n")
print("="*70)
print("       EXTERNAL IP CLASSIFICATION MODULE")
print("="*70)
print("\nPublic IPs require additional analysis.")
print("Performing DNS Resolution and Organization Lookup.")
print("\nPlease wait for 30-40 seconds (sometimes) while the IDS verifies the IP ownership.")
print("-"*70)
for current_ip in ip_to_packets:
    try:
        ip_object=ipaddress.ip_address(
                    current_ip
                    )
        if ip_object.is_private:
            private_ips.append(
                current_ip
                )
            ip_organization[
                current_ip
                ]="PRIVATE NETWORK"
        else:
            try:
                host_name=socket.gethostbyaddr(
                            current_ip
                            )[0]
                host_name=host_name.lower()
                organization_found=False
                for organization in known_organizations:
                    for keyword in known_organizations[
                            organization
                            ]:
                        if keyword in host_name:
                            known_public_ips.append(
                                    current_ip
                                    )
                            ip_organization[
                                current_ip
                                ]=organization
                            organization_found=True
                            break
                    if organization_found:
                        break
                    if not organization_found:
                        unknown_public_ips.append(
                                current_ip
                                )
                        ip_organization[
                                current_ip
                                ]=host_name
                    known_public_ips.append(
                        current_ip
                        )

                    ip_organization[
                        current_ip
                        ]=host_name
                else:

                    unknown_public_ips.append(
                        current_ip
                        )
                    ip_organization[
                        current_ip
                        ]=host_name
            except:

                unknown_public_ips.append(
                    current_ip
                    )
                ip_organization[
                    current_ip
                    ]="UNVERIFIED"
    except:
        unknown_ips.append(current_ip)
        ip_organization[
            current_ip
            ]="UNKNOWN"
print("\n")
print("="*60)
print("UNKNOWN EXTERNAL IP DETECTION")
print("="*60)
print("\nPRIVATE IPS")
print("-"*40)
if len(private_ips)==0:
    print("No Private IPs Found.")
else:
    for current_ip in private_ips:
        print("\nIP :", current_ip)
        print("Packets :",ip_to_packets[current_ip])
        print("Organization: ",ip_organization[current_ip])
        print("Status : SAFE")
        print("-"*40)
print("\nKNOWN PUBLIC IPS")
print("-"*40)
if len(known_public_ips)==0:
    print("No Public IPs Found.")
else:
    for current_ip in known_public_ips:
        print("\nIP :",current_ip)
        print("Packets :",ip_to_packets[current_ip])
        print("Status : VERIFIED PUBLIC IP")
        print("Organization: ",ip_organization[current_ip])
        print("Recommendation :")
        print("SAFE")
        print("-"*40)
print("\nUNKNOWN PUBLIC IPS")
print("-"*40)
if len(unknown_public_ips)==0:
    print("No Unknown PUBLIC IPs Found.")
else:
    for current_ip in unknown_public_ips:
        print("\nIP :", current_ip)
        print("Packets :", ip_to_packets[current_ip])
        print("Organization: ",ip_organization[current_ip])
        print("Status : UNVERIFIED")
        print("Recommendation :")
        print("Need monitoring")
        print("-"*40)
print("\nUNKNOWN IPS")
print("-"*40)
if len(unknown_ips)==0:
    print("No Unknown IPs Found.")
else:
    for current_ip in unknown_ips:
        print("\nIP :", current_ip)
        print("Packets :", ip_to_packets[current_ip])
        print("Organization: ",ip_organization[current_ip])
        print("Status : UNKNOWN")
        print("Recommendation :")
        print("Please monitor once")
        print("-"*40)
        #login detect
print("\n")
print("="*60)
print("FAILED LOGIN DETECTION")
print("="*60)
if len(failed_login_ips)==0:
    print("\nNO FAILED LOGIN ATTEMPTS DETECTED.")
else:
    for ip in failed_login_ips:
        print("\nWARNING !!!")
        print("IP :",
            ip)
        print("Packets :",
            ip_to_packets[ip])
        print("Packets/sec :",
            round(
                    packets_per_second[ip],
                    2))
        print("Time Taken :",
            round(
                    time_taken[ip],
                    2),
            "seconds")
        print("Sensitive Login Port Accessed : YES")
        print("Reason :")
        print("Possible Brute Force Login Attempt Detected.")
        print("-"*40)
        #alerts
for ip in ip_to_packets:
    score=0
    if ip in failed_login_ips:
        score+=50
    if ip in suspicious_port_scan_ips:
        score+=40
    elif ip in port_scan_ips:
        score+=20
    if ip in packet_spike_ips:
        score+=30
    if ip in  high_traffic_ips:
        score+=20
    score+=risk_scores[ip]
    if score>=120:
        critical_alert_ips.append(ip)
    elif score>=80:
        high_alert_ips.append(ip)
    elif score>=50:
        medium_alert_ips.append(ip)
    elif score>20:
        low_alert_ips.append(ip)
print("\n")
print("="*60)
print("FINAL ALERT SYSTEM")
print("="*60)

print("\nLOW ALERTS")
print("-"*40)
if len(low_alert_ips)==0:
    print("No Low Alerts Found.")
else:
    for ip in low_alert_ips:
        print(ip)
        print("Risk Score out of 160:",
              risk_scores[ip])

print("\nMEDIUM ALERTS")
print("-"*40)
if len(medium_alert_ips)==0:
    print("No Medium Alerts Found.")
else:
    for ip in medium_alert_ips:
        print(ip)
        print("Risk Score out of 160:",
              risk_scores[ip])

print("\nHIGH ALERTS")
print("-"*40)
if len(high_alert_ips)==0:
    print("No High Alerts Found.")
else:
    for ip in high_alert_ips:
        print(ip)
        print("Risk Score out of 160:",
        risk_scores[ip])

print("\nCRITICAL ALERTS")
print("-"*40)
if len(critical_alert_ips)==0:
    print("No Critical Alerts Found.")
else:
    for ip in critical_alert_ips:
        print("\nWARNING !!!")
        print("IP :",ip)
        print("Risk Score out of 160:",
              risk_scores[ip])
        print("Immediate Investigation Recommended.")
        print("-"*40)      
print("\nSUMMARY")
print("-"*70)
print("\n")
print("="*60)
print("FINAL SECURITY REPORT")
print("="*60)
print("\nNETWORK SUMMARY")
print("-"*40)
print("Total Packets :",
      len(packets))
print("Source IPs :",
      len(source_ips))
print("Destination IPs :",
      len(destination_ips))
print("Protocols Found :",
      len(protocols))
print("Most Active IP :",
      most_active_ip)
print("\n")
print("-"*40)
print("SECURITY ANALYSIS SUMMARY")
print("-"*40)
print("Low Alerts :",
      len(low_alert_ips))
print("Medium Alerts :",
      len(medium_alert_ips))
print("High Alerts :",
      len(high_alert_ips))
print("Critical Alerts :",
      len(critical_alert_ips))
print("\n")
print("-"*40)
print("MODULE EXECUTION STATUS")
print("-"*40)
print("[SUCCESS] Packet Analysis")
print("[SUCCESS] Risk Analysis")
print("[SUCCESS] Time Analysis")
print("[SUCCESS] High Traffic Detection")
print("[SUCCESS] Packet Spike Detection")
print("[SUCCESS] Port Scan Detection")
print("[SUCCESS] Failed Login Detection")
print("[SUCCESS] External IP Classification")
print("[SUCCESS] Alert System")
print("\n")
print("-"*40)
print("SECURITY STATUS")
print("-"*40)
if len(critical_alert_ips)>0:
    print("\nCRITICAL THREATS DETECTED !!!")
    print("Immediate Investigation Required.")
elif len(high_alert_ips)>0:
    print("\nHIGH RISK TRAFFIC DETECTED.")
    print("Monitoring Recommended.")
else:
    print("\nNO CRITICAL THREATS DETECTED.")
    print("Network Appears Secure.")
print("\n")
print("="*60)
print("NETWORK INTRUSION DETECTION SYSTEM")
print("VERSION 1.0")
print("\nANALYSIS COMPLETED SUCCESSFULLY.")
print("="*60)
print("\nThank you for using NIDS Version 1.0")
print("="*70)