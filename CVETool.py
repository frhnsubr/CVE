import pyfiglet
import sys
import socket
from datetime import datetime
from timeit import default_timer as timer
from bs4 import BeautifulSoup
import requests

ascii_banner = pyfiglet.figlet_format("CVE Tool") #Font change to ASCII art
print(ascii_banner)
open_ports = [] #Array created to store open ports

target = input("Enter your hostname or IP address for scanning: ")
target_ip = socket.gethostbyname(target) #This is to convert hostname into IP address
low_range = input("Enter Port Start Range = ")
high_range = input("Enter Port Stop Range = ")

print("-" * 70)
print("Scanning Target: " + target_ip) #Display target IP in IP format
print("Scanning started at:" + str(datetime.now())) #Show date and time
print("-" * 70)

try:
    start = timer() #Timer function used to check how long the loop is working

    # will scan ports between 1 to 65,535
    for port in range(int(low_range), int(high_range)): #Run the loop from port start range to stop range
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #socket allows one to work with network sockets
        #AF_INET specifies address family like IPv4
        #SOCK_STREAM specifies that it will be used for streaming data
        socket.setdefaulttimeout(1)
        #within 1 second response must be received from host, if not error is thrown
        result = s.connect_ex((target_ip, port))
        #connect_ex attempts to make TCP connection based on the given IP/Port
        if result == 0:
            print("Port {} is open".format(port))
            open_ports.append(port)
        s.close()
    end = timer() #Calculate end time once loop is exited
    elapsed_time = end - start #Calculate total time taken for the loop

    print("Scan Completed Successfully")
    print("\nElapsed Scanning Time: ", elapsed_time, "seconds")
    print("\nCommencing CVE Database lookup...Please Standby")
    with open("vulnerabilities.html", "w") as f: #opening a .html file with write permission
        # Write the HTML header
        f.write("<html><title>Vulnerabilities Report</title><body>") #html format for vulnerability report
        f.write(f"<h1><center>CVE Vulnerabilities Report</center></h1>")
        for portt in open_ports: #Iterate through all open ports stored in array

            f.write(f"<h2>Vulnerabilities Existing in port {portt}</h2>")
            print("\nVulnerabilities Existing in port", portt)
            url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=port+{portt}" #The main url to actual website (changes are made to port number)
            response = requests.get(url) #HTTP GET request sent to url
            soup = BeautifulSoup(response.content, "html.parser") #Setting webscraper to parse HTML webpage
            lists = soup.find("div", {"id": "TableWithRules"}) #find specific tags under which actual CVE data resides
            rows = lists.find_all("tr") #This lists out Name and Description of CVE
            f.write("<ol>") #To create ordered list
            for row in rows[1:11]: #1 is to ignore Name/Description as header and top 10 CVE will be printed
                print(row.get_text(strip=True))
                f.write(f"<li>{row.get_text()}</li>")
            f.write("</ol>")
        f.write("</body></html>")
    print("\nTask Completed Successfully, Generated CVE Vulnerability Report!")

except KeyboardInterrupt: #Allows you to exit out of program
    print("\n Exiting Program !!!!")
    sys.exit()
except socket.gaierror: #Get address info error
    print("\n Hostname Could Not Be Resolved !!!!")
    sys.exit()
except socket.error: #General Socket errors will be caught here
    print("\n Server not responding !!!!")
    sys.exit()
#frhnsubr