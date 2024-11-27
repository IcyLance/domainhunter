#!/usr/bin/env python

## Title:       domainhunter.py
## Author:      @joevest and @andrewchiles
## Description: Checks expired domains, reputation/categorization, and Archive.org history to determine 
##              good candidates for phishing and C2 domain names

# If the expected response format from a provider changes, use the traceback module to get a full stack trace without removing try/catch blocks
#import traceback
#traceback.print_exc()

from module import *
import time
import argparse
import os
from urllib.parse import urlparse
import getpass

 # Load dependent modules
try:
    import requests
    from bs4 import BeautifulSoup
    from texttable import Texttable
    
except Exception as e:
    print("Expired Domains Reputation Check")
    print("[-] Missing basic dependencies: {}".format(str(e)))
    print("[*] Install required dependencies by running `pip3 install -r requirements.txt`")
    quit(0)

__version__ = "20221025"

#Functions
def solveCaptcha(url, session):  
    """Downloads CAPTCHA image and saves to current directory for OCR with tesseract"""
    
    jpeg = 'captcha.jpg'
    
    try:
        response = session.get(url=url,headers=headers,verify=False, stream=True,proxies=proxies)
        if response.status_code == 200:
            with open(jpeg, 'wb') as f:
                response.raw.decode_content = True
                shutil.copyfileobj(response.raw, f)
        else:
            print('[-] Error downloading CAPTCHA file!')
            return False

        # Perform basic OCR without additional image enhancement
        text = pytesseract.image_to_string(Image.open(jpeg))
        text = text.replace(" ", "").rstrip()
        
        # Remove CAPTCHA file
        try:
            os.remove(jpeg)
        except OSError:
            pass

        return text

    except Exception as e:
        print("[-] Error solving CAPTCHA - {0}".format(e))
        
        return False

def drawTable(header, data):
    """Generates a text based table for printing to the console"""
    data.insert(0,header)
    t = Texttable(max_width=args.maxwidth)
    t.add_rows(data)
    t.header(header)
    
    return(t.draw())

## MAIN
if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='Finds expired domains, domain categorization, and Archive.org history to determine good candidates for C2 and phishing domains',
        epilog = '''
            Examples:
            ./domainhunter.py -k apples -c --ocr -t5
            ./domainhunter.py --check --ocr -t3
            ./domainhunter.py --single mydomain.com
            ./domainhunter.py --keyword tech --check --ocr --timing 5 --alexa
            ./domaihunter.py --filename inputlist.txt --ocr --timing 5''',
                    formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-a','--alexa', help='Filter results to Alexa listings', required=False, default=0, action='store_const', const=1)
    parser.add_argument('-k','--keyword', help='Keyword used to refine search results', required=False, default=False, type=str, dest='keyword')
    parser.add_argument('-c','--check', help='Perform domain reputation checks', required=False, default=False, action='store_true', dest='check')
    parser.add_argument('-f','--filename', help='Specify input file of line delimited domain names to check', required=False, default=False, type=str, dest='filename')
    parser.add_argument('--ocr', help='Perform OCR on CAPTCHAs when challenged', required=False, default=False, action='store_true')
    parser.add_argument('-r','--maxresults', help='Number of results to return when querying latest expired/deleted domains', required=False, default=100, type=int, dest='maxresults')
    parser.add_argument('-s','--single', help='Performs detailed reputation checks against a single domain name/IP.', required=False, default=False, dest='single')
    parser.add_argument('-t','--timing', help='Modifies request timing to avoid CAPTCHAs. Slowest(0) = 90-120 seconds, Default(3) = 10-20 seconds, Fastest(5) = no delay', required=False, default=3, type=int, choices=range(0,6), dest='timing')
    parser.add_argument('-w','--maxwidth', help='Width of text table', required=False, default=400, type=int, dest='maxwidth')
    parser.add_argument('-V','--version', action='version',version='%(prog)s {version}'.format(version=__version__))
    parser.add_argument("-P", "--proxy", required=False, default=None, help="proxy. ex https://127.0.0.1:8080")
    parser.add_argument("-u", "--username", required=False, default=None, type=str, help="username for expireddomains.net")
    parser.add_argument("-p", "--password", required=False, default=None, type=str, help="password for expireddomains.net")
    parser.add_argument("-o", "--output", required=False, default=None, type=str, help="output file path")
    parser.add_argument('-ks','--keyword-start', help='Keyword starts with used to refine search results', required=False, default="", type=str, dest='keyword_start')
    parser.add_argument('-ke','--keyword-end', help='Keyword ends with used to refine search results', required=False, default="", type=str, dest='keyword_end')
    parser.add_argument('-um','--umbrella-apikey', help='API Key for umbrella (paid)', required=False, default="", type=str, dest='umbrella_apikey')
    parser.add_argument('-q','--quiet', help='Surpress initial ASCII art and header', required=False, default=False, action='store_true', dest='quiet')
    args = parser.parse_args()

   

    # Load OCR related modules if --ocr flag is set since these can be difficult to get working
    if args.ocr:
        try:
            import pytesseract
            from PIL import Image
            import shutil
        except Exception as e:
            print("Expired Domains Reputation Check")
            print("[-] Missing OCR dependencies: ", str(e))
            print("[*] Install required Python dependencies by running: pip3 install -r requirements.txt")
            print(r"[*] Ubuntu\Debian - Install tesseract by running: apt-get install tesseract-ocr python3-imaging")
            print("[*] macOS - Install tesseract with homebrew by running: brew install tesseract")
            quit(0)
    
    ## Variables
    malwaredomainsURL = 'https://gitlab.com/gerowen/old-malware-domains-ad-list/-/raw/master/malwaredomainslist.txt'
    expireddomainsqueryURL = 'https://www.expireddomains.net/domain-name-search'
    expireddomainHost = "https://member.expireddomains.net"

    proxies = {}

    requests.packages.urllib3.disable_warnings()
 
    # HTTP Session container, used to manage cookies, session tokens and other session information
    s = requests.Session()

    if(args.proxy != None):
        proxy_parts = urlparse(args.proxy)
        proxies["http"] = "http://%s" % (proxy_parts.netloc)
        proxies["https"] = "https://%s" % (proxy_parts.netloc)
    s.proxies = proxies
    title = r'''
 ____   ___  __  __    _    ___ _   _   _   _ _   _ _   _ _____ _____ ____  
|  _ \ / _ \|  \/  |  / \  |_ _| \ | | | | | | | | | \ | |_   _| ____|  _ \ 
| | | | | | | |\/| | / _ \  | ||  \| | | |_| | | | |  \| | | | |  _| | |_) |
| |_| | |_| | |  | |/ ___ \ | || |\  | |  _  | |_| | |\  | | | | |___|  _ < 
|____/ \___/|_|  |_/_/   \_\___|_| \_| |_| |_|\___/|_| \_| |_| |_____|_| \_\ '''

    # Print header
    if not (args.quiet):
        print(title)
        print('''\nExpired Domains Reputation Checker
Authors: @joevest and @andrewchiles\n
DISCLAIMER: This is for educational purposes only!
It is designed to promote education and the improvement of computer/cyber security.  
The authors or employers are not liable for any illegal act or misuse performed by any user of this tool.
If you plan to use this content for illegal purpose, don't.  Have a nice day :)\n''')

    # Download known malware domains
    # print('[*] Downloading malware domain list from {}\n'.format(malwaredomainsURL))
    
    maldomains = downloadMalwareDomains(malwaredomainsURL, s)
    maldomainsList = maldomains.split("\n")

    # Retrieve reputation for a single choosen domain (Quick Mode)
    if args.single:
        checkDomain(args.single, maldomainsList, args)
        exit(0)

    # Perform detailed domain reputation checks against input file, print table, and quit. This does not generate an HTML report
    if args.filename:
        # Initialize our list with an empty row for the header
        data = []
        try:
            with open(args.filename, 'r') as domainsList:
                for line in domainsList.read().splitlines():
                    data.append(checkDomain(line, maldomainsList, args))
                    doSleep(args.timing)

                # Print results table
                header = ['Domain', 'BlueCoat', 'IBM X-Force', 'Cisco Talos', 'Umbrella', 'McAfee Web Gateway (Cloud)']
                print(drawTable(header,data))

        except KeyboardInterrupt:
            print('Caught keyboard interrupt. Exiting!')
            exit(0)
        except Exception as e:
            print('[-] Error: ', e)
            exit(1)
        exit(0)

    # Lists for our ExpiredDomains results
    domain_list = []
    data = []

    # Generate list of URLs to query for expired/deleted domains
    urls = []
    if args.username == None or args.username == "":
        print('[-] Error: ExpiredDomains.net requires a username! Use the --username parameter')
        exit(1)
    if args.password == None or args.password == "":
        args.password = getpass.getpass("expireddomains.net Password: ")

    loginExpiredDomains(s, args)
    
    m = 200
    if args.maxresults < m:
        m = args.maxresults

    for i in range (0,(args.maxresults),m):
        k=""
        if args.keyword:
            k=args.keyword
        urls.append('{}/domains/combinedexpired/?fwhois=22&fadult=1&start={}&ftlds[]=2&ftlds[]=3&ftlds[]=4&flimit={}&fdomain={}&fdomainstart={}&fdomainend={}&falexa={}'.format(expireddomainHost,i,m,k,args.keyword_start,args.keyword_end,args.alexa))

    max_reached = False
    for url in urls:

        print("[*] ", url)

        domainrequest = s.get(url, headers=header, verify=False, proxies=proxies)
        domains = domainrequest.text

        # Turn the HTML into a Beautiful Soup object
        soup = BeautifulSoup(domains, 'html.parser')

        try:
            table = soup.find_all("table", class_="base1")
            tbody = table[0].select("tbody tr")

            for row in tbody:
                # Alternative way to extract domain name
                # domain = row.find('td').find('a').text

                cells = row.findAll("td")
                
                if len(cells) == 1:
                    max_reached = True
                    break # exit if max rows reached
            
                if len(cells) >= 1:
                    c0 = getIndex(cells, 0).lower()   # domain
                    c1 = getIndex(cells, 3)   # bl
                    c2 = getIndex(cells, 4)   # domainpop
                    c3 = getIndex(cells, 5)   # birth
                    c4 = getIndex(cells, 7)   # Archive.org entries
                    c5 = getIndex(cells, 8)   # Alexa
                    c6 = getIndex(cells, 10)  # Dmoz.org
                    c7 = getIndex(cells, 12)  # status com
                    c8 = getIndex(cells, 13)  # status net
                    c9 = getIndex(cells, 14)  # status org
                    c10 = getIndex(cells, 17)  # status de
                    c11 = getIndex(cells, 11)  # TLDs
                    c12 = getIndex(cells, 19)  # RDT
                    c13 = ""                    # List
                    c14 = getIndex(cells, 22)  # Status
                    c15 = ""                    # links

                    # create available TLD list
                    available = ''
                    if c7 == "available":
                        available += ".com "

                    if c8 == "available":
                        available += ".net "

                    if c9 == "available":
                        available += ".org "

                    if c10 == "available":
                        available += ".de "
                    
                    # Only grab status for keyword searches since it doesn't exist otherwise
                    status = ""
                    if args.keyword:
                        status = c14

                    if args.keyword:
                        # Only add Expired, not Pending, Backorder, etc
                        # "expired" isn't returned any more, I changed it to "available"
                        if c14 == "available": # I'm not sure about this, seems like "expired" isn't an option anymore.  expireddomains.net might not support this any more.
                            # Append parsed domain data to list if it matches our criteria (.com|.net|.org and not a known malware domain)
                            if (c0.lower().endswith(".com") or c0.lower().endswith(".net") or c0.lower().endswith(".org")) and (c0 not in maldomainsList):
                                domain_list.append([c0,c3,c4,available,status])
                        
                    # Non-keyword search table format is slightly different
                    else:
                        # Append original parsed domain data to list if it matches our criteria (.com|.net|.org and not a known malware domain)
                        if (c0.lower().endswith(".com") or c0.lower().endswith(".net") or c0.lower().endswith(".org")) and (c0 not in maldomainsList):
                            domain_list.append([c0,c3,c4,available,status]) 
            if max_reached:
                print("[*] All records returned")
                break

        except Exception as e: 
            print("[!] Error: ", e)
            pass

        # Add additional sleep on requests to ExpiredDomains.net to avoid errors
        time.sleep(5)

    # Check for valid list results before continuing
    if len(domain_list) == 0:
        print("[-] No domain results found or none are currently available for purchase!")
        exit(0)
    else:
        domain_list_unique = []
        [domain_list_unique.append(item) for item in domain_list if item not in domain_list_unique]

        # Print number of domains to perform reputation checks against
        if args.check:
            print("\n[*] Performing reputation checks for {} domains".format(len(domain_list_unique)))
            print("")

        for domain_entry in domain_list_unique:
            domain = domain_entry[0]
            birthdate = domain_entry[1]
            archiveentries = domain_entry[2]
            availabletlds = domain_entry[3]
            status = domain_entry[4]
            bluecoat = '-'
            ibmxforce = '-'
            ciscotalos = '-'
            umbrella = '-'

            # Perform domain reputation checks
            if args.check:
                unwantedResults = ['Uncategorized','error','Not found.','Spam','Spam URLs','Pornography','badurl','Suspicious','Malicious Sources/Malnets','captcha','Phishing','Placeholders']
                
                bluecoat = checkBluecoat(domain, s, args)
                if bluecoat not in unwantedResults:
                    print("[+] Bluecoat - {}: {}".format(domain, bluecoat))
                
                ibmxforce = checkIBMXForce(domain, s)
                if ibmxforce not in unwantedResults:
                    print("[+] IBM XForce - {}: {}".format(domain, ibmxforce))
                
                ciscotalos = checkTalos(domain, s)
                if ciscotalos not in unwantedResults:
                    print("[+] Cisco Talos {}: {}".format(domain, ciscotalos))

                if len(args.umbrella_apikey):
                    umbrella = checkUmbrella(domain, s, args)
                    if umbrella not in unwantedResults:
                        print("[+] Umbrella {}: {}".format(domain, umbrella))

                mcafeewg = checkMcAfeeWG(domain, proxies)
                if mcafeewg not in unwantedResults:
                    print("[+] McAfee Web Gateway (Cloud) {}: {}".format(domain, mcafeewg))

                print("")
                # Sleep to avoid captchas
                doSleep(args.timing)

            # Append entry to new list with reputation if at least one service reports reputation
            if not (\
                (bluecoat in ('Uncategorized','badurl','Suspicious','Malicious Sources/Malnets','captcha','Phishing','Placeholders','Spam','error')) \
                and (ibmxforce in ('Not found.','error')) \
                and (ciscotalos in ('Uncategorized','error')) \
                and (umbrella in ('Uncategorized','None')) \
                and (mcafeewg in ('Uncategorized','error'))):
                
                data.append([domain,birthdate,archiveentries,availabletlds,status,bluecoat,ibmxforce,ciscotalos,umbrella,mcafeewg])

    # Sort domain list by column 2 (Birth Year)
    sortedDomains = sorted(data, key=lambda x: x[1], reverse=True) 

    if args.check:
        if len(sortedDomains) == 0:
            print("[-] No domains discovered with a desireable categorization!")
            exit(0)
        else:
            print("[*] {} of {} domains discovered with a potentially desireable categorization!".format(len(sortedDomains),len(domain_list)))

    # Build HTML Table
    html = ''
    htmlHeader = '<html><head><title>Expired Domain List</title></head>'
    htmlBody = '<body><p>The following available domains report was generated at {}</p>'.format(timestamp)
    htmlTableHeader = '''
                
                 <table border="1" align="center">
                    <th>Domain</th>
                    <th>Birth</th>
                    <th>Entries</th>
                    <th>TLDs Available</th>
                    <th>Status</th>
                    <th>BlueCoat</th>
                    <th>IBM X-Force</th>
                    <th>Cisco Talos</th>
                    <th>Umbrella</th>
                    <th>WatchGuard</th>
                    <th>Namecheap</th>
                    <th>Archive.org</th>
                 '''

    htmlTableBody = ''
    htmlTableFooter = '</table>'
    htmlFooter = '</body></html>'

    # Build HTML table contents
    for i in sortedDomains:
        htmlTableBody += '<tr>'
        htmlTableBody += '<td>{}</td>'.format(i[0]) # Domain
        htmlTableBody += '<td>{}</td>'.format(i[1]) # Birth
        htmlTableBody += '<td>{}</td>'.format(i[2]) # Entries
        htmlTableBody += '<td>{}</td>'.format(i[3]) # TLDs
        htmlTableBody += '<td>{}</td>'.format(i[4]) # Status

        htmlTableBody += '<td><a href="https://sitereview.bluecoat.com/" target="_blank">{}</a></td>'.format(i[5]) # Bluecoat
        htmlTableBody += '<td><a href="https://exchange.xforce.ibmcloud.com/url/{}" target="_blank">{}</a></td>'.format(i[0],i[6]) # IBM x-Force Categorization
        htmlTableBody += '<td><a href="https://www.talosintelligence.com/reputation_center/lookup?search={}" target="_blank">{}</a></td>'.format(i[0],i[7]) # Cisco Talos
        htmlTableBody += '<td>{}</td>'.format(i[8]) # Cisco Umbrella
        htmlTableBody += '<td><a href="https://sitelookup.mcafee.com/en/feedback/url?action=checksingle&url=http%3A%2F%2F{}&product=14-ts" target="_blank">{}</a></td>'.format(i[0],i[9]) # McAfee Web Gateway (Cloud)
        htmlTableBody += '<td><a href="http://www.borderware.com/domain_lookup.php?ip={}" target="_blank">WatchGuard</a></td>'.format(i[0]) # Borderware WatchGuard
        htmlTableBody += '<td><a href="https://www.namecheap.com/domains/registration/results.aspx?domain={}" target="_blank">Namecheap</a></td>'.format(i[0]) # Namecheap
        htmlTableBody += '<td><a href="http://web.archive.org/web/*/{}" target="_blank">Archive.org</a></td>'.format(i[0]) # Archive.org
        htmlTableBody += '</tr>'

    html = htmlHeader + htmlBody + htmlTableHeader + htmlTableBody + htmlTableFooter + htmlFooter

    logfilename = "{}_domainreport.html".format(timestamp)
    if args.output != None:
        logfilename = args.output

    log = open(logfilename,'w')
    log.write(html)
    log.close

    print("\n[*] Search complete")
    print("[*] Log written to {}\n".format(logfilename))
    
    # Print Text Table
    header = ['Domain', 'Birth', '#', 'TLDs', 'Status', 'BlueCoat', 'IBM', 'Cisco Talos', 'Umbrella']
    print(drawTable(header,sortedDomains))