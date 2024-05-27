import webbrowser
import sublist3r
import colorama
from colorama import Fore, Style
import requests
from urllib.parse import quote

# Initialize colorama
colorama.init()

def open_website(url):
    webbrowser.open(url)

def get_subdomains(domain):
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    return subdomains

def sub_save_to_file(subdomains, filename):
    with open(filename, 'w') as file:
        for subdomain in subdomains:
            file.write(subdomain + "\n")

def check_url_status(file_path):
    try:
        with open(file_path, 'r') as file:
            urls = file.readlines()
            for url in urls:
                url = url.strip()
                try:
                    response = requests.head(url, allow_redirects=True, timeout=10)
                    if response.status_code == 200:
                        print(Fore.GREEN +"[+] "+ f"{url} - Status: 200 OK" + Style.RESET_ALL)
                    elif response.status_code == 403:
                        print(Fore.YELLOW +"[=] "+ f"{url} - Status: 403 Forbidden" + Style.RESET_ALL)
                    elif response.status_code == 404:
                        print(Fore.RED +"[-] "+ f"{url} - Status: 404 Not Found" + Style.RESET_ALL)
                    else:
                        print(Fore.CYAN +"[#] "+ f"{url} - Status: {response.status_code}" + Style.RESET_ALL)
                except requests.ConnectionError:
                    print(Fore.RED +"[-] "+ f"{url} - Connection Error" + Style.RESET_ALL)
                except requests.Timeout:
                    print(Fore.RED +"[-] "+ f"{url} - Timeout Error" + Style.RESET_ALL)
                except requests.RequestException as e:
                    print(Fore.RED +"[-] "+ f"{url} - Error: {e}" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + "[-] File not found." + Style.RESET_ALL)

def google_dorks_scan(domain, option):
    base_url = "https://www.google.com/search?q="
    search_query = ""

    if option == "1":
        search_query = f"site:{domain} intitle:\"Index of /\""
    elif option == "2":
        search_query = f"site:{domain} intitle:\"index of /config\""
    elif option == "3":
        search_query = f"site:{domain} intitle:\"index of /database\""
    elif option == "4":
        search_query = f"site:{domain} intitle:\"index of /wp-content\""
    elif option == "5":
        search_query = f"site:{domain} inurl:wp-content"
    elif option == "6":
        search_query = f"site:{domain} intitle:\"index of /logs\""
    elif option == "7":
        search_query = f"site:{domain} intitle:\"index of /backup\""
    elif option == "8":
        search_query = f"site:{domain} intitle:\"Login page\""
    elif option == "9":
        search_query = f"site:{domain} intitle:\"Admin login\""
    elif option == "10":
        search_query = f"site:{domain} intitle:\"SQL Error\""
    elif option == "11":
        search_query = f"site:{domain} intitle:\"Apache config\""
    elif option == "12":
        search_query = f"site:{domain} inurl:robots.txt"
    elif option == "13":
        search_query = f"site:{domain} filetype:json"
    elif option == "14":
        search_query = f"site:{domain} inurl:package.json"
    elif option == "15":
        search_query = f"site:{domain} intitle:\"index of\" \"parent directory\" \"public\""
    elif option == "16":
        search_query = f"site:{domain} phpinfo()"
    elif option == "17":
        search_query = f"site:{domain} intitle:\"backdoor\""
    elif option == "18":
        search_query = f"site:{domain} intitle:\"install\" OR intitle:\"setup\""
    elif option == "19":
        search_query = f"site:{domain} inurl:redir OR inurl:redirect"
    elif option == "20":
        search_query = f"site:{domain} intitle:\"Apache Struts 2 Documentation\""
    elif option == "21":
        search_query = f"site:{domain} \"3rd party\""
    elif option == "22":
        search_query = f"site:{domain} intitle:\"index of /\" \".htaccess\""
    elif option == "23":
        search_query = f"site:{domain} inurl:\"/*\""
    elif option == "24":
        search_query = f"site:{domain} inurl:\"/*/*\""
    elif option == "25":
        search_query = f"site:{domain} inurl:crossdomain.xml"
    elif option == "26":
        search_query = f"site:{domain} inurl:\"*.swf\""
    elif option == "27":
        search_query = f"site:{domain} intitle:\"Traefik Dashboard\""
    elif option == "28":
        search_query = f"site:{domain} intitle:\"index of\" \"parent directory\" \"cloud\""
    elif option == "29":
        search_query = f"site:{domain} inurl:\"aws s3\""
    elif option == "30":
        search_query = f"site:{domain} inurl:\"wsdl\""
    else:
        print(Fore.RED + "[-] Invalid option." + Style.RESET_ALL)
        return

    encoded_query = quote(search_query)
    search_url = base_url + encoded_query

    open_website(search_url)
    print(Fore.GREEN + f"[+] Google Dorks search opened for option {option}" + Style.RESET_ALL)

def whois_info(domain):
    whois_url = f"https://www.whois.com/whois/{domain}"
    open_website(whois_url)
    print(Fore.GREEN + f"[+] WHOIS information opened for {domain}")

def search_admin_page(domain):
    search_url = f"https://www.google.com/search?q=site:{domain}+admin"
    open_website(search_url)
    print(Fore.GREEN + f"[+] Google search opened for site:{domain} admin")

def netcraft_report(domain):
    netcraft_url = f"https://sitereport.netcraft.com/?url={domain}"
    open_website(netcraft_url)
    print(Fore.GREEN + f"[+] Netcraft site report opened for {domain}")

def dns_info(domain):
    dns_url = f"https://mxtoolbox.com/SuperTool.aspx?action=dns%3a{domain}"
    open_website(dns_url)
    print(Fore.GREEN + f"[+] DNS information opened for {domain}")

def ssl_info(domain):
    ssl_url = f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}"
    open_website(ssl_url)
    print(Fore.GREEN + f"[+] SSL certificate information opened for {domain}")

def website_headers(domain):
    try:
        response = requests.head(f"https://{domain}")
        print(Fore.GREEN + f"[+] HTTP headers for {domain}:\n")
        for header, value in response.headers.items():
            print(Fore.CYAN + f"{header}: {value}")
    except requests.RequestException as e:
        print(Fore.GREEN+ f"[+] Error fetching headers: {e}")

def security_headers(domain):
    security_headers_url = f"https://securityheaders.com/?q={domain}&followRedirects=on"
    open_website(security_headers_url)
    print(Fore.GREEN + f"[+] Security headers report opened for {domain}")

def open_redirects(domain):
    open_redirects_url = f"https://www.redirect-checker.org/index.php?url={domain}"
    open_website(open_redirects_url)
    print(Fore.GREEN + f"[+] Open redirects check report opened for {domain}")

def malware_scan(domain):
    malware_scan_url = f"https://sitecheck.sucuri.net/results/{domain}"
    open_website(malware_scan_url)
    print(Fore.GREEN + f"[+] Malware scan report opened for {domain}")

def pagespeed_insights(domain):
    pagespeed_url = f"https://developers.google.com/speed/pagespeed/insights/?url=https://{domain}"
    open_website(pagespeed_url)
    print(Fore.GREEN+ f"[+] PageSpeed Insights report opened for {domain}")

def broken_link_checker(domain):
    broken_link_url = f"https://www.brokenlinkcheck.com/broken-links.php#status"
    open_website(broken_link_url)
    print(Fore.GREEN+ f"[+] Broken link check report opened for {domain}")

def mobile_friendly_test(domain):
    mobile_friendly_url = f"https://search.google.com/test/mobile-friendly?url=https://{domain}"
    open_website(mobile_friendly_url)
    print(Fore.GREEN+ f"[+] Mobile-friendly test report opened for {domain}")

def whois_history(domain):
    whois_history_url = f"https://viewdns.info/iphistory/?domain={domain}"
    open_website(whois_history_url)
    print(Fore.GREEN+ f"[+] WHOIS history report opened for {domain}")

def blacklist_check(domain):
    blacklist_check_url = f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{domain}"
    open_website(blacklist_check_url)
    print(Fore.GREEN+ f"[+] Blacklist check report opened for {domain}")

def website_technologies(domain):
    website_technologies_url = f"https://builtwith.com/{domain}"
    open_website(website_technologies_url)
    print(Fore.GREEN+ f"[+] Website technologies report opened for {domain}")

def website_uptime(domain):
    uptime_url = f"https://www.isitdownrightnow.com/{domain}.html"
    open_website(uptime_url)
    print(Fore.GREEN+ f"[+] Website uptime check opened for {domain}")

def csp_check(domain):
    csp_url = f"https://csp-evaluator.withgoogle.com/?csp=https://{domain}"
    open_website(csp_url)
    print(Fore.GREEN+ f"[+] Content Security Policy check opened for {domain}")

def open_ports_check(domain):
    open_ports_url = f"https://hackertarget.com/nmap-online-port-scanner/?q={domain}"
    open_website(open_ports_url)
    print(Fore.GREEN+ f"[+] Open ports check report opened for {domain}")

def seo_analysis(domain):
    seo_url = f"https://neilpatel.com/seo-analyzer/?url={domain}"
    open_website(seo_url)
    print(Fore.GREEN+ f"[+] SEO analysis report opened for {domain}")

def cookie_check(domain):
    cookie_url = f"https://www.cookieserve.com/?site={domain}"
    open_website(cookie_url)
    print(Fore.GREEN+ f"[+] Cookie check report opened for {domain}")

def javascript_errors(domain):
    js_errors_url = f"https://www.site24x7.com/tools/javascript-errors-checker.html?url={domain}"
    open_website(js_errors_url)
    print(Fore.GREEN+ f"[+] JavaScript errors check report opened for {domain}")

def w3c_validation(domain):
    w3c_url = f"https://validator.w3.org/nu/?doc=https://{domain}"
    open_website(w3c_url)
    print(Fore.GREEN+ f"[+] W3C validation report opened for {domain}")

def google_safe_browsing(domain):
    safe_browsing_url = f"https://transparencyreport.google.com/safe-browsing/search?url={domain}"
    open_website(safe_browsing_url)
    print(Fore.GREEN+ f"[+] Google Safe Browsing check opened for {domain}")

def google_analytics_check(domain):
    ga_check_url = f"https://www.gachecker.com/?q=https://{domain}"
    open_website(ga_check_url)
    print(Fore.GREEN+ f"[+] Google Analytics check report opened for {domain}")

def subdomain_enumeration(domain):
    subdomain_url = f"https://www.virustotal.com/gui/domain/{domain}/details"
    open_website(subdomain_url)
    print(Fore.GREEN+ f"[+] Subdomain enumeration report opened for {domain}")

def quick_scan(domain):

    # Perform the tasks
    print("\n" + Fore.GREEN + "[+] Please Wait ..." + Style.RESET_ALL + "\n")
    whois_info(domain)
    search_admin_page(domain)
    netcraft_report(domain)
    dns_info(domain)
    ssl_info(domain)
    website_headers(domain)
    security_headers(domain)
    open_redirects(domain)
    malware_scan(domain)
    output_file = "subdomains/"+domain+".txt"
    subdomains = get_subdomains(domain)
    sub_save_to_file(subdomains, output_file)
    print("\n" + Fore.GREEN + "[+] Saved to /subdomains/"+domain+".txt" + Style.RESET_ALL)

def custom_scan(domain, choices):
    if '0' in choices:
        choices = [str(i) for i in range(1, 26)]

    if '1' in choices:
        whois_info(domain)
    if '2' in choices:
        search_admin_page(domain)
    if '3' in choices:
        netcraft_report(domain)
    if '4' in choices:
        dns_info(domain)
    if '5' in choices:
        ssl_info(domain)
    if '6' in choices:
        website_headers(domain)
    if '7' in choices:
        security_headers(domain)
    if '8' in choices:
        subdomain_enumeration(domain)
    if '9' in choices:
        open_redirects(domain)
    if '10' in choices:
        malware_scan(domain)
    if '11' in choices:
        pagespeed_insights(domain)
    if '12' in choices:
        broken_link_checker(domain)
    if '13' in choices:
        mobile_friendly_test(domain)
    if '14' in choices:
        whois_history(domain)
    if '15' in choices:
        blacklist_check(domain)
    if '16' in choices:
        website_technologies(domain)
    if '17' in choices:
        website_uptime(domain)
    if '18' in choices:
        csp_check(domain)
    if '19' in choices:
        open_ports_check(domain)
    if '20' in choices:
        seo_analysis(domain)
    if '21' in choices:
        cookie_check(domain)
    if '22' in choices:
        javascript_errors(domain)
    if '23' in choices:
        w3c_validation(domain)
    if '24' in choices:
        google_safe_browsing(domain)
    if '25' in choices:
        google_analytics_check(domain)

def social_web_scan(domain, option):
    if option == "1":
        search_url = f"https://domaineye.com/search/{domain}"
    elif option == "2":
        search_url = f"https://securityheaders.com/?q={domain}&followRedirects=on"
    elif option == "3":
        search_url = f"https://pastebin.com/search?q={domain}"
    elif option == "4":
        search_url = f"https://www.linkedin.com/search/results/people/?keywords={domain}"
    elif option == "5":
        search_url = f"https://bitbucket.org/search?q={domain}"
    elif option == "6":
        search_url = f"https://www.atlassian.com/search/results?query={domain}"
    elif option == "7":
        search_url = f"https://stackoverflow.com/search?q={domain}"
    elif option == "8":
        search_url = f"https://www.passivetotal.org/search?query={domain}"
    elif option == "9":
        search_url = f"https://web.archive.org/web/*/https://{domain}"
    elif option == "10":
        search_url = f"https://github.com/search?q={domain}"
    elif option == "11":
        search_url = f"https://openbugbounty.org/search/?search={domain}"
    elif option == "12":
        search_url = f"https://www.reddit.com/search/?q={domain}"
    elif option == "13":
        search_url = f"https://www.threatcrowd.org/domain.php?domain={domain}"
    elif option == "14":
        search_url = f"https://www.youtube.com/results?search_query={domain}"
    elif option == "15":
        search_url = f"https://www.digitalocean.com/spaces/{domain}"
    elif option == "16":
        search_url = f"https://yandex.com/search/?text=site:{domain}+filetype:swf"
    elif option == "17":
        search_url = f"https://web.archive.org/web/*/http://{domain}/*.swf"
    elif option == "18":
        search_url = f"https://web.archive.org/web/*/http://{domain}/*/*.swf"
    elif option == "19":
        search_url = f"https://web.archive.org/web/*/http://{domain}/*/*/*.swf"
    elif option == "20":
        search_url = f"https://viewdns.info/reverseip/?host={domain}&t=1"
    elif option == "21":
        search_url = f"https://publicwww.com/websites/{domain}"
    elif option == "22":
        search_url = f"https://censys.io/ipv4?q={domain}"
    elif option == "23":
        search_url = f"https://censys.io/domain?q={domain}"
    elif option == "24":
        search_url = f"https://censys.io/certs?q={domain}"
    elif option == "25":
        search_url = f"https://www.shodan.io/search?query={domain}"
    elif option == "26":
        search_url = "https://www.exploit-db.com/exploits/48152"
    elif option == "27":
        search_url = f"https://gist.github.com/search?q={domain}"
    elif option == "28":
        search_url = f"https://crt.sh/?q={domain}"
    elif option == "29":
        search_url = f"https://www.google.com/search?q=site:pastebin.com+{domain}"
    elif option == "30":
        search_url = f"https://whatcms.org/?s={domain}"
    elif option == "31":
        search_url = f"https://www.whois.com/whois/{domain}"
    else:
        print(Fore.RED + "[-] Invalid option.")
        return
    
    open_website(search_url)
    print(Fore.GREEN + f"[+] Search Opened for Option {option}")

def bug_search(query):
    try:
        base_url = "https://www.google.com/search?q="
        encoded_query = quote(query)
        search_url = base_url + encoded_query

        webbrowser.open_new_tab(search_url)
        print(Fore.GREEN + f"[+] Google search opened for query: {query}" + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"[-] Error opening URL: {e}" + Style.RESET_ALL)

def search_server_vulnerabilities():
    server_name = input(Fore.YELLOW + "[+] Enter Server Name: ").strip()
    server_version = input(Fore.YELLOW + "[+] Enter Server Version: ").strip()

    query = f"{server_name} {server_version} vulnerability"
    bug_search(query)

def search_php_vulnerabilities():
    php_script_name = input(Fore.YELLOW + "[+] Enter PHP Script Name: ").strip()
    php_version = input(Fore.YELLOW + "[+] Enter PHP Version: ").strip()

    query = f"{php_script_name} {php_version} vulnerability"
    bug_search(query)

def search_wordpress_vulnerabilities():
    print(Fore.CYAN + "1. Search Plugin Vulnerability\n"
        "2. Search Theme Vulnerability\n" + Style.RESET_ALL)
    option = input(
        Fore.YELLOW +"Your choice: "
    ).strip()

    if option == "1":
        plugin_name = input(Fore.YELLOW + "[+] Enter Plugin Name: ").strip()
        plugin_version = input(Fore.YELLOW + "[+] Enter Plugin Version (if known, else leave blank): ").strip()

        query = f"wordpress {plugin_name} {plugin_version} vulnerability"
        bug_search(query)

    elif option == "2":
        theme_name = input(Fore.YELLOW + "[+] Enter Theme Name: ").strip()
        theme_version = input(Fore.YELLOW + "[+] Enter Theme Version (if known, else leave blank): ").strip()

        query = f"wordpress {theme_name} {theme_version} theme vulnerability"
        bug_search(query)

    else:
        print(Fore.RED + "[-] Invalid option." + Style.RESET_ALL)

print(Fore.RED + """
   _____  _                  _      _____              _               
  / ____|| |                | |    / ____|            | |              
 | |  __ | |__    ___   ___ | |_  | (___    ___   ___ | | __ ___  _ __ 
 | | |_ || '_ \  / _ \ / __|| __|  \___ \  / _ \ / _ \| |/ // _ \| '__|
 | |__| || | | || (_) |\__ \| |_   ____) ||  __/|  __/|   <|  __/| |   
  \_____||_| |_| \___/ |___/ \__| |_____/  \___| \___||_|\_\\\___||_| 
         
                                                - By Developer Rishi
      
                                           github.com/DeveloperRishi
""" + Style.RESET_ALL)


while True:
    print(Fore.GREEN + "\n1. Google Dorks Search")
    print("2. Online Web-Tools and Social Search")
    print("3. Subdomain Finder")
    print("4. Urls Status Checker")
    print("5. Quick Scan")
    print("6. Custom Scan")
    print("7. Bug Search")
    query = input("\n" + Fore.YELLOW + "[+] Enter your choice: " + Style.RESET_ALL)

    if query == "1":
        print("\n" + Fore.CYAN + "1. Directory Listing")
        print("2. Configuration Files")
        print("3. Database Files")
        print("4. Wordpress")
        print("5. Wordpress (2)")
        print("6. Log Files")
        print("7. Backup and Old Files")
        print("8. Login Pages")
        print("9. Admin Login Pages")
        print("10. SQL Errors")
        print("11. Apache Config Files")
        print("12. Robots.txt File")
        print("13. .json File")
        print("14. package.json File")
        print("15. Publicly Exposed Documents")
        print("16. phpinfo()")
        print("17. Find Backdoors")
        print("18. Install or Setup Files")
        print("19. Open Redirects")
        print("20. Apache STRUTS RCE")
        print("21. 3rd Party Exposure")
        print("22. .htaccess Sensitive Files")
        print("23. Find Subdomains")
        print("24. Find Sub-Subdomains")
        print("25. Test Cross Domain")
        print("26. Find .SWF file")
        print("27. Traefik")
        print("28. Cloud Storage and Buckets")
        print("29. s3 AWS Buckets")
        print("30. API Endpoints [WSDL]" + Style.RESET_ALL)

        option = input(Fore.YELLOW + "\n[+] Your option: ").strip()
        domain = input(Fore.YELLOW + "[+] Enter Target Domain (example.com): ")
        Style.RESET_ALL
        google_dorks_scan(domain, option)
    elif query == "2":
        print("\n" + Fore.CYAN + "1. Domain EYE")
        print("2. Check Security Headers")
        print("3. Find Pastebin Entries")
        print("4. Employees on Linkedin")
        print("5. Search in Bitbucket")
        print("6. Search in Atlassian")
        print("7. Search in Stackoverflow")
        print("8. Search in PassiveTotal")
        print("9. Find Wordpress [Wayback Machine]")
        print("10. Search in Github")
        print("11. Search in OpenBugBounty")
        print("12. Search in Reddit")
        print("13. Check in Threat Crowd")
        print("14. Search in Youtube")
        print("15. Search Digital Ocean Spaces")
        print("16. Find .SWF file in Yandex")
        print("17. Find .SWF file in Wayback")
        print("18. Find .SWF file in Wayback (2)")
        print("19. Find .SWF file in Wayback (3)")
        print("20. Reverse IP Lookup")
        print("21. Sourcecode [PublicWWW]")
        print("22. Check in CENSYS [IPv4]")
        print("23. Check in CENSYS [Domains]")
        print("24. Check in CENSYS [CERTS]")
        print("25. Search in Shodan")
        print("26. CVE-2020-0646 SharePoint RCE")
        print("27. Github GIST Search")
        print("28. Search in CRT Logs")
        print("29. Plaintext Password Leak")
        print("30. What CMS")
        print("31. Who is" + Style.RESET_ALL)

        option = input(Fore.YELLOW + "\n[+] Your option: ").strip()
        domain = input(Fore.YELLOW + "[+] Enter Target Domain (example.com): ")
        Style.RESET_ALL
        social_web_scan(domain, option)
    elif query == "3":
        domain = input("\n" + Fore.YELLOW + "[+] Enter Target Domain: ")
        Style.RESET_ALL
        output_file = "subdomains/"+domain+".txt"
        print("\n" + Fore.GREEN + "[+] Please Wait ..." + Style.RESET_ALL + "\n")
        subdomains = get_subdomains(domain)
        for subdomain in subdomains:
            print(Fore.GREEN + "[+] " + subdomain + Style.RESET_ALL)
        sub_save_to_file(subdomains, output_file)
        print("\n" + Fore.GREEN + "[+] Saved to /subdomains/"+domain+".txt" + Style.RESET_ALL)
    elif query == "4":
        file_path = input("\n" + Fore.YELLOW + "[+] Enter path to file with URLs: ")
        Style.RESET_ALL
        print(Fore.CYAN + "[+] Checking URLs status..." + Style.RESET_ALL)
        check_url_status(file_path)
        print(Style.RESET_ALL)
    elif query == "5":
        domain = input("\n" + Fore.YELLOW + "[+] Enter Target Domain (example.com): ")
        Style.RESET_ALL
        quick_scan(domain)
    elif query == "6":
        print(Fore.CYAN + "Select the scans to perform:")
        print("1. WHOIS Information")
        print("2. Google Search for Admin Pages")
        print("3. Netcraft Site Report")
        print("4. DNS Information")
        print("5. SSL Certificate Information")
        print("6. Website Headers Check")
        print("7. Security Headers Check")
        print("8. Subdomain Enumeration")
        print("9. Open Redirects Check")
        print("10. Malware Scan")
        print("11. PageSpeed Insights")
        print("12. Broken Link Checker")
        print("13. Mobile-Friendly Test")
        print("14. WHOIS History")
        print("15. Blacklist Check")
        print("16. Website Technologies")
        print("17. Website Uptime Check")
        print("18. Content Security Policy Check")
        print("19. Open Ports Check")
        print("20. SEO Analysis")
        print("21. Cookie Check")
        print("22. JavaScript Errors Check")
        print("23. W3C Validation")
        print("24. Google Safe Browsing")
        print("25. Google Analytics Check"+ Style.RESET_ALL)
        print(Fore.RED + "0. Perform All Scans"+ Style.RESET_ALL)
        print(Fore.YELLOW + "Enter the numbers of the scans you want to perform, separated by commas (e.g., 1,2,3):")

        choices = input("\n[+] Your choices: ").split(',')
        domain = input("[+] Enter Target Domain (example.com): ")
        Style.RESET_ALL
        custom_scan(domain, choices)

    elif query == "7":
        print(Fore.CYAN + "1. Search Server Vulnerability")
        print("2. Search PHP Script Vulnerability")
        print("3. Search WordPress Plugin or Theme Vulnerability"+ Style.RESET_ALL)

        option = input(Fore.YELLOW + "\n[+] Your option: ").strip()
        if option == "1":
            search_server_vulnerabilities()
        elif option == "2":
            search_php_vulnerabilities()
        elif option == "3":
            search_wordpress_vulnerabilities()
        else:
            print(Fore.RED + "[-] Invalid option." + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] Invalid choice. Please enter a valid option." + Style.RESET_ALL)
