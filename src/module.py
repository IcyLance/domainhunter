import time
import random
import json
import base64
import sys
from hashlib import sha256
from domainhunter import solveCaptcha

try:
    import requests
    from bs4 import BeautifulSoup
        
except Exception as e:
    print("Expired Domains Reputation Check")
    print("[-] Missing basic dependencies: {}".format(str(e)))
    print("[*] Install required dependencies by running `pip3 install -r requirements.txt`")
    quit(0)

# Variables
useragent = 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)'
headers = {'User-Agent':useragent}
timestamp = time.strftime("%Y%m%d_%H%M%S")

def doSleep(timing):
    """Add nmap like random sleep interval for multiple requests"""

    if timing == 0:
        time.sleep(random.randrange(90,120))
    elif timing == 1:
        time.sleep(random.randrange(60,90))
    elif timing == 2:
        time.sleep(random.randrange(30,60))
    elif timing == 3:
        time.sleep(random.randrange(10,20))
    elif timing == 4:
        time.sleep(random.randrange(5,10))
    # There's no elif timing == 5 here because we don't want to sleep for -t 5

def checkUmbrella(domain, s, args):
    """Umbrella Domain reputation service"""

    try:
        url = 'https://investigate.api.umbrella.com/domains/categorization/?showLabels'
        postData = [domain]

        headers = {
            'User-Agent':useragent,
            'Content-Type':'application/json; charset=UTF-8',
            'Authorization': 'Bearer {}'.format(args.umbrella_apikey)
        }

        print('[*] Umbrella: {}'.format(domain))
        
        response = s.post(url,headers=headers,json=postData,verify=False,proxies=s.proxies)
        responseJSON = json.loads(response.text)
        if len(responseJSON[domain]['content_categories']) > 0:
            return responseJSON[domain]['content_categories'][0]
        else:
            return 'Uncategorized'

    except Exception as e:
        print('[-] Error retrieving Umbrella reputation! {0}'.format(e))
        return "error"

def checkBluecoat(domain, s, args):
    """Symantec Sitereview Domain Reputation"""

    try:
        headers = {
            'User-Agent':useragent,
            'Referer':'http://sitereview.bluecoat.com/'}

        # Establish our session information
        response = s.get("https://sitereview.bluecoat.com/",headers=headers,verify=False,proxies=s.proxies)
        response = s.head("https://sitereview.bluecoat.com/resource/captcha-request",headers=headers,verify=False,proxies=s.proxies)
        
        # Pull the XSRF Token from the cookie jar
        session_cookies = s.cookies.get_dict()
        if "XSRF-TOKEN" in session_cookies:
            token = session_cookies["XSRF-TOKEN"]
        else:
            raise NameError("No XSRF-TOKEN found in the cookie jar")
 
        # Perform SiteReview lookup
        
        # BlueCoat Added base64 encoded phrases selected at random and sha256 hashing of the JSESSIONID
        phrases = [
            'UGxlYXNlIGRvbid0IGZvcmNlIHVzIHRvIHRha2UgbWVhc3VyZXMgdGhhdCB3aWxsIG1ha2UgaXQgbW9yZSBkaWZmaWN1bHQgZm9yIGxlZ2l0aW1hdGUgdXNlcnMgdG8gbGV2ZXJhZ2UgdGhpcyBzZXJ2aWNlLg==',
            'SWYgeW91IGNhbiByZWFkIHRoaXMsIHlvdSBhcmUgbGlrZWx5IGFib3V0IHRvIGRvIHNvbWV0aGluZyB0aGF0IGlzIGFnYWluc3Qgb3VyIFRlcm1zIG9mIFNlcnZpY2U=',
            'RXZlbiBpZiB5b3UgYXJlIG5vdCBwYXJ0IG9mIGEgY29tbWVyY2lhbCBvcmdhbml6YXRpb24sIHNjcmlwdGluZyBhZ2FpbnN0IFNpdGUgUmV2aWV3IGlzIHN0aWxsIGFnYWluc3QgdGhlIFRlcm1zIG9mIFNlcnZpY2U=',
            'U2NyaXB0aW5nIGFnYWluc3QgU2l0ZSBSZXZpZXcgaXMgYWdhaW5zdCB0aGUgU2l0ZSBSZXZpZXcgVGVybXMgb2YgU2VydmljZQ=='
        ]
        
        # New Bluecoat XSRF Code added May 2022 thanks to @froyo75
        xsrf_token_parts = token.split('-')
        xsrf_random_part = random.choice(xsrf_token_parts)
        key_data = xsrf_random_part + ': ' + token
        # Key used as part of POST data
        key = sha256(key_data.encode('utf-8')).hexdigest()
        random_phrase = base64.b64decode(random.choice(phrases)).decode('utf-8')
        phrase_data = xsrf_random_part + ': ' + random_phrase
        # Phrase used as part of POST data
        phrase = sha256(phrase_data.encode('utf-8')).hexdigest()
        
        postData = {
            'url':domain,
            'captcha':'',
            'key':key,
            'phrase':phrase, # Pick a random base64 phrase from the list
            'source':'new-lookup'}

        headers = {'User-Agent':useragent,
                   'Accept':'application/json, text/plain, */*',
                   'Accept-Language':'en_US',
                   'Content-Type':'application/json; charset=UTF-8',
                   'X-XSRF-TOKEN':token,
                   'Referer':'http://sitereview.bluecoat.com/'}

        print('[*] BlueCoat: {}'.format(domain))
        response = s.post('https://sitereview.bluecoat.com/resource/lookup',headers=headers,json=postData,verify=False,proxies=s.proxies)
        
        # Check for any HTTP errors
        if response.status_code != 200:
            a = "HTTP Error ({}-{}) - Is your IP blocked?".format(response.status_code,response.reason)
        else:
            responseJSON = json.loads(response.text)
        
            if 'errorType' in responseJSON:
                a = responseJSON['errorType']
            else:
                a = responseJSON['categorization'][0]['name']
        
            # Print notice if CAPTCHAs are blocking accurate results and attempt to solve if --ocr
            if a == 'captcha':
                if args.ocr:
                    # This request is also performed by a browser, but is not needed for our purposes
                    #captcharequestURL = 'https://sitereview.bluecoat.com/resource/captcha-request'

                    print('[*] Received CAPTCHA challenge!')
                    captcha = solveCaptcha('https://sitereview.bluecoat.com/resource/captcha.jpg',s)
                    
                    if captcha:
                        b64captcha = base64.urlsafe_b64encode(captcha.encode('utf-8')).decode('utf-8')
                    
                        # Send CAPTCHA solution via GET since inclusion with the domain categorization request doesn't work anymore
                        captchasolutionURL = 'https://sitereview.bluecoat.com/resource/captcha-request/{0}'.format(b64captcha)
                        print('[*] Submiting CAPTCHA at {0}'.format(captchasolutionURL))
                        response = s.get(url=captchasolutionURL,headers=headers,verify=False,proxies=s.proxies)

                        # Try the categorization request again

                        response = s.post('https://sitereview.bluecoat.com/resource/lookup',headers=headers,json=postData,verify=False,proxies=s.proxies)

                        responseJSON = json.loads(response.text)

                        if 'errorType' in responseJSON:
                            a = responseJSON['errorType']
                        else:
                            a = responseJSON['categorization'][0]['name']
                    else:
                        print('[-] Error: Failed to solve BlueCoat CAPTCHA with OCR! Manually solve at "https://sitereview.bluecoat.com/sitereview.jsp"')
                else:
                    print('[-] Error: BlueCoat CAPTCHA received. Try --ocr flag or manually solve a CAPTCHA at "https://sitereview.bluecoat.com/sitereview.jsp"')
        return a

    except Exception as e:
        print('[-] Error retrieving Bluecoat reputation! {0}'.format(e))
        return "error"

def checkIBMXForce(domain, s):
    """IBM XForce Domain Reputation"""

    try: 
        url = 'https://exchange.xforce.ibmcloud.com/url/{}'.format(domain)
        headers = {'User-Agent':useragent,
                    'Accept':'application/json, text/plain, */*',
                    'x-ui':'XFE',
                    'Origin':url,
                    'Referer':url}

        print('[*] IBM xForce: {}'.format(domain))

        url = 'https://api.xforce.ibmcloud.com/url/{}'.format(domain)
        response = s.get(url,headers=headers,verify=False,proxies=s.proxies)

        responseJSON = json.loads(response.text)

        if 'error' in responseJSON:
            a = responseJSON['error']

        elif not responseJSON['result']['cats']:
            a = 'Uncategorized'
	
	## TO-DO - Add noticed when "intrusion" category is returned. This is indication of rate limit / brute-force protection hit on the endpoint        

        else:
            categories = ''
            # Parse all dictionary keys and append to single string to get Category names
            for key in responseJSON['result']['cats']:
                categories += '{0}, '.format(str(key))

            a = '{0}(Score: {1})'.format(categories,str(responseJSON['result']['score']))

        return a

    except Exception as e:
        print('[-] Error retrieving IBM-Xforce reputation! {0}'.format(e))
        return "error"

def checkTalos(domain, s):
    """Cisco Talos Domain Reputation"""

    url = 'https://www.talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fdomain%2F&query_entry={0}&offset=0&order=ip+asc'.format(domain)
    headers = {'User-Agent':useragent,
               'Referer':url}

    print('[*] Cisco Talos: {}'.format(domain))
    try:
        response = s.get(url,headers=headers,verify=False,proxies=s.proxies)

        responseJSON = json.loads(response.text)

        if 'error' in responseJSON:
            a = str(responseJSON['error'])
            if a == "Unfortunately, we can't find any results for your search.":
                a = 'Uncategorized'
        
        elif responseJSON['category'] is None:
            a = 'Uncategorized'

        else:
            a = '{0} (Score: {1})'.format(str(responseJSON['category']['description']), str(responseJSON['web_score_name']))
       
        return a

    except Exception as e:
        print('[-] Error retrieving Talos reputation! {0}'.format(e))
        return "error"

def checkMcAfeeWG(domain, proxies):
    """McAfee Web Gateway Domain Reputation"""

    try:
        print('[*] McAfee Web Gateway (Cloud): {}'.format(domain))

        # HTTP Session container, used to manage cookies, session tokens and other session information
        s = requests.Session()

        headers = {
                'User-Agent':useragent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Referer':'https://sitelookup.mcafee.com/'
                }  

        # Establish our session information
        response = s.get("https://sitelookup.mcafee.com",headers=headers,verify=False,proxies=proxies)

        # Pull the hidden attributes from the response
        soup = BeautifulSoup(response.text,"html.parser")
        hidden_tags = soup.find_all("input",  {"type": "hidden"})
        for tag in hidden_tags:
            if tag['name'] == 'sid':
                sid = tag['value']
            elif tag['name'] == 'e':
                e = tag['value']
            elif tag['name'] == 'c':
                c = tag['value']
            elif tag['name'] == 'p':
                p = tag['value']

        # Retrieve the categorization infos 
        multipart_form_data = {
            'sid': (None, sid),
            'e': (None, e),
            'c': (None, c),
            'p': (None, p),
            'action': (None, 'checksingle'),
            'product': (None, '14-ts'),
            'url': (None, domain)
        }

        response = s.post('https://sitelookup.mcafee.com/en/feedback/url',headers=headers,files=multipart_form_data,verify=False,proxies=proxies)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text,"html.parser")
            for table in soup.findAll("table", {"class": ["result-table"]}):
                datas = table.find_all('td')
                if "not valid" in datas[2].text:
                    a = 'Uncategorized'
                else:
                    status = datas[2].text
                    category = (datas[3].text[1:]).strip().replace('-',' -')
                    web_reputation = datas[4].text
                    a = '{0}, Status: {1}, Web Reputation: {2}'.format(category,status,web_reputation)
            return a
        else:
            raise Exception

    except Exception as e:
        print('[-] Error retrieving McAfee Web Gateway Domain Reputation!')
        return "error"

def downloadMalwareDomains(malwaredomainsURL, s):
    """Downloads a current list of known malicious domains"""

    url = malwaredomainsURL
    response = s.get(url=url,headers=headers,verify=False,proxies=s.proxies)
    responseText = response.text
    if response.status_code == 200:
        return responseText
    else:
        print("[-] Error reaching:{}  Status: {}").format(url, response.status_code)

def checkDomain(domain, maldomainsList, args):
    """Executes various domain reputation checks included in the project"""

    print('[*] Fetching domain reputation for: {}'.format(domain))

    if domain in maldomainsList:
        print("[!] {}: Identified as known malware domain (malwaredomains.com)".format(domain))
      
    bluecoat = checkBluecoat(domain)
    print("[+] {}: {}".format(domain, bluecoat))
    
    ibmxforce = checkIBMXForce(domain)
    print("[+] {}: {}".format(domain, ibmxforce))

    ciscotalos = checkTalos(domain)
    print("[+] {}: {}".format(domain, ciscotalos))

    umbrella = "not available"
    if len(args.umbrella_apikey):
        umbrella = checkUmbrella(domain)
        print("[+] {}: {}".format(domain, umbrella))

    mcafeewg = checkMcAfeeWG(domain)
    print("[+] {}: {}".format(domain, mcafeewg))

    print("")
    
    results = [domain,bluecoat,ibmxforce,ciscotalos,umbrella,mcafeewg]
    return results

def loginExpiredDomains(s, args):
    """Login to the ExpiredDomains site with supplied credentials"""

    expireddomainHost = "https://member.expireddomains.net"

    data = "login=%s&password=%s&redirect_2_url=/begin" % (args.username, args.password)
    
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    r = s.post(expireddomainHost + "/login/", headers=headers, data=data, proxies=s.proxies, verify=False, allow_redirects=False)
    cookies = s.cookies.get_dict()

    if "location" in r.headers:
        if "/login/" in r.headers["location"]:
            print("[!] Login failed")
            sys.exit()

    if "ExpiredDomainssessid" in cookies:
        print("[+] Login successful.  ExpiredDomainssessid: %s" % (cookies["ExpiredDomainssessid"]))
    else:
        print("[!] Login failed")
        sys.exit()

def getIndex(cells, index):
        if cells[index].find("a") == None:
            return cells[index].text.strip()
        
        return cells[index].find("a").text.strip()