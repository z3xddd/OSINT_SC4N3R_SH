#!/usr/bin/env python3
#
# OsInT Sc4N3r - Tool for automated single host recon process
# @author: Israel C. dos Reis [@z3xddd]

from os import popen, geteuid

class OsInT_Sc4N3r(object):
    def __init__(self, domain):
        self.domain = domain
    
    def validate_run_as_root(self):
        if not geteuid() == 0:
            print("[-] Please run this script as root... [-]")
            exit()
        else:
            pass

    def create_folder_results(self):
        validate_folder_command = "ls -la"
        validate_var = popen(validate_folder_command).read()
        if "results" in validate_var:
            pass
        else:
            results_command = 'mkdir results'
            print('[+] Creating folder /results to archive logs... [+]')
            popen(results_command)
            print('[+] Folder created... [+]')

    def enumerate_webservers(self):
        enumerate_command = 'echo '+self.domain+' | httpx --silent > results/result_httpx_'+self.domain+'.txt'
        print("[*] Httpx execute process starting... [*]")
        print(popen(enumerate_command).read())
        print('[+] Httpx scan finished... See details on results/result_httpx_'+self.domain+'.txt [+]')

    def portscan(self):
        portscan_command = 'nmap -sSV -n -f -Pn T 3 --script=/usr/share/nmap/scripts/firewall-bypass.nse --allports --randomize-hosts --data-length 127 '+self.domain+' > results/result_portscan_'+self.domain+'.txt'
        print("[*] Portscan execute process starting... [*]")
        popen(portscan_command).read()
        print('[+] Portscan scan finished... See details on results/result_portscan_'+self.domain+'.txt [+]')

    def search_json(self):
        search_json_command = 'echo '+self.domain+' |  waybackurls | grep -E "\.json(?:onp?)?$" | anew > results/result_search_json_'+self.domain+'.txt'
        print("[*] Search .json files execute process starting... [*]")
        popen(search_json_command).read()
        print('[+] Scan finished... See details on results/result_search_json_'+self.domain+'.txt [+]')

    def search_js(self):
        search_js_command = 'echo '+self.domain+' |  waybackurls | grep -E "\.js(?:onp?)?$" | anew > results/result_search_js_'+self.domain+'.txt'
        print("[*] Search .js files execute process starting... [*]")
        popen(search_js_command).read()
        print('[+] Scan finished... See details on results/result_search_js_'+self.domain+'.txt [+]')

    def search_xml(self):
        search_xml_command = 'echo '+self.domain+' |  waybackurls | grep -E "\.xml(?:onp?)?$" | anew > results/result_search_xml_'+self.domain+'.txt'
        print("[*] Search .xml files execute process starting... [*]")
        popen(search_xml_command).read()
        print('[+] Scan finished... See details on results/result_search_xml_'+self.domain+'.txt [+]')
    
    def search_php(self):
        search_php_command = 'echo '+self.domain+' |  waybackurls | grep -E "\.php(?:onp?)?$" | anew > results/result_search_php_'+self.domain+'.txt'
        print("[*] Search .php files execute process starting... [*]")
        popen(search_php_command).read()
        print('[+] Scan finished... See details on results/result_search_php_'+self.domain+'.txt [+]')

    def search_txt(self):
        search_txt_command = 'echo '+self.domain+' |  waybackurls | grep -E "\.txt(?:onp?)?$" | anew > results/result_search_txt_'+self.domain+'.txt'
        print("[*] Search .txt files execute process starting... [*]")
        popen(search_txt_command).read()
        print('[+] Scan finished... See details on results/result_search_txt_'+self.domain+'.txt [+]')

    def search_aspx(self):
        search_aspx_command = 'echo '+self.domain+' |  waybackurls | grep -E "\.aspx(?:onp?)?$" | anew > results/result_search_aspx_'+self.domain+'.txt'
        print("[*] Search .aspx files execute process starting... [*]")
        popen(search_aspx_command).read()
        print('[+] Scan finished... See details on results/result_search_aspx_'+self.domain+'.txt [+]')
        
    def search_xhtml(self):
        search_xhtml_command = 'echo '+self.domain+' |  waybackurls | grep -E "\.xhtml(?:onp?)?$" | anew > results/result_search_xhtml_'+self.domain+'.txt'
        print("[*] Search .xhtml files execute process starting... [*]")
        popen(search_xhtml_command).read()
        print('[+] Scan finished... See details on results/result_search_xhtml_'+self.domain+'.txt [+]')

    def search_ini(self):
        search_ini_command = 'echo '+self.domain+' |  waybackurls | grep -E "\.ini(?:onp?)?$" | anew > results/result_search_ini_'+self.domain+'.txt'
        print("[*] Search .ini files execute process starting... [*]")
        popen(search_ini_command).read()
        print('[+] Scan finished... See details on results/result_search_ini_'+self.domain+'.txt [+]')

    def xss_scan(self):
        xss_command = 'echo '+self.domain+' |  waybackurls | kxss > results/result_xss_scan_'+self.domain+'.txt'
        print("[*] XSS Scan execute process starting... [*]")
        popen(xss_command).read()
        print('[+] XSS Scan finished... See details on results/result_xss_scan_'+self.domain+'.txt [+]')

    def sqli_scan(self):
        sqli_command = 'sqlmap -u "'+self.domain+'" --random-agent --crawl=10 --answers="follow=Y" --batch --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,percentage,randomcase,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes -v 3 > results/result_sqli_scan_'+self.domain+'.txt'
        print("[*] SQL INJECTION Scan execute process starting... [*]")
        popen(sqli_command).read()
        print('[+] SQL INJECTION Scan finished... See details on results/result_sqli_scan_'+self.domain+'.txt [+]')

    def nuclei_attack(self):
        attack_command = 'nuclei -l results/result_httpx_'+self.domain+'.txt -t ../nuclei-templates/ > results/result_nuclei_'+self.domain+'.txt'
        print("[*] Nuclei attack execute process starting... [*]")
        print(popen(attack_command).read())
        print('[+] Nuclei attack finished... See details on results/result_nuclei_'+self.domain+'.txt [+]')

    
    

print("""\
:'#######:::'######::'####:'##::: ##:'########:::::'######:::'######::'##::::::::'##::: ##::'#######::'########::
'##.... ##:'##... ##:. ##:: ###:: ##:... ##..:::::'##... ##:'##... ##: ##:::'##:: ###:: ##:'##.... ##: ##.... ##:
 ##:::: ##: ##:::..::: ##:: ####: ##:::: ##::::::: ##:::..:: ##:::..:: ##::: ##:: ####: ##:..::::: ##: ##:::: ##:
 ##:::: ##:. ######::: ##:: ## ## ##:::: ##:::::::. ######:: ##::::::: ##::: ##:: ## ## ##::'#######:: ########::
 ##:::: ##::..... ##:: ##:: ##. ####:::: ##::::::::..... ##: ##::::::: #########: ##. ####::...... ##: ##.. ##:::
 ##:::: ##:'##::: ##:: ##:: ##:. ###:::: ##:::::::'##::: ##: ##::: ##:...... ##:: ##:. ###:'##:::: ##: ##::. ##::
. #######::. ######::'####: ##::. ##:::: ##:::::::. ######::. ######:::::::: ##:: ##::. ##:. #######:: ##:::. ##:
:.......::::......:::....::..::::..:::::..:::::::::......::::......:::::::::..:::..::::..:::.......:::..:::::..::
                                                                   
#################################################################################################################                                                                   
                                                                     Tool for automated single host recon process
                                                                                 by: Israel C. dos Reis [@z3xddd]
    """)
user_domain_input = str(input("[+] Enter domain to scan >>  [ EX: domain.com.br ]  "))
domain_to_scan = OsInT_Sc4N3r(user_domain_input)
domain_to_scan.validate_run_as_root()
domain_to_scan.create_folder_results()
domain_to_scan.enumerate_webservers()
domain_to_scan.search_json()
domain_to_scan.search_js()
domain_to_scan.search_xml()
domain_to_scan.search_php()
domain_to_scan.search_txt()
domain_to_scan.search_aspx()
domain_to_scan.search_xhtml()
domain_to_scan.search_ini()
domain_to_scan.xss_scan()
domain_to_scan.nuclei_attack()
domain_to_scan.portscan()