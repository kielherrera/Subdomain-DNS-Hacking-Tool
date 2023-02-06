import dns.resolver
import dns.reversename
import socket
import dns.zone

header = '''For all your DNS needs,

This DNS cheat sheet collated good resources on the internet so you wouldn’t have to. Different DNS enumeration tools from command-line tools such as Dig, Host, Dirb, and Nmap
to Online Vulnerability Scanners were tackled with an aim to not give a disheartening time to those just starting out on their journey to become ethical hackers.

Note:
    The following are just the basics. Once mastered, you can check the manual page by using the man command to find out all the possible uses and options.
    Nslookup would not be tackled here but learning it is beneficial as it is a cross-platform software that would likely be available at your disposal regardless of your machine.
    Nslookup Resources: https://www.hostinger.ph/tutorials/what-is-nslookup

'''

dig = '''DNSing using Dig
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
The Dig syntax in its most simplest form…

    dig [@server] [name] [type] [options]

        [@server]
            the IP address or hostname of the name server to query
		    [Optional] By default uses the name server listed in /etc/resolv.conf
		    
        [name]
            the resource to be looked up
        
        [type]
            the type of query. A, ANY, MX, NS, SOA, HINFO, AXFR, TXT, ...
            [Optional] By default performs a lookup for an A record
        
        [options]
            +short, +noall, +answer
            [Optional] By default displays the installed dig version, technical details about the answers, statistics about the query, a question section along with few other ones

Usage Examples
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Digging a Domain Name
    > dig google.com
    Note: uses the default option for [@server], [type], and [options]

Specifying Nameservers
    > dig @8.8.8.8 google.com
    Use When: you want to query a resource using a particular nameserver

Batch Queries
    > dig -f domain_name.txt
    Use When: you want to perform a DNS lookup for a list of domains

Search for a Record Type
    > dig google.com MX
    Use When: you want to look up a specific record (available DNS record types above)

Query All DNS Record Types
    > dig google.com ANY
    Use When: you want to query all the available DNS record types

Trace DNS Path
    > dig google.com +trace
    Use When: you want to trace the DNS lookup path

Reverse DNS Lookup
    > dig -x 172.217.24.110
    Use When: you want to look up the domain and hostname associated with an IP address

DNS Zone Transfer
    > dig axfr zonetransfer.me @nsztm1.digi.ninja
    Use When: you have a name server of a domain and want to get the full DNS zone of the target

Short Answers
    > dig google.com +short
    Use When: you only want the result of the query

Detailed Answers
    > dig google.com +noall +answer
    Use When: you only want to view the answers section in detail

Control Dig Behavior
    > echo "+noall +answer" > ~/.digrc
    Use When: you are planning to use a specific command all the time without having to type it in while executing the query
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

'''

otherTools = '''DNSing using Host, Dirb, and Nmap
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
IPv6 Address
    > host google.com
    Use When: you want to find the IPv6 address of a particular domain

Enumerating Subdomain 
    > dirb https://google.com/ subdomain_name.txt
    Use When: you want to enumerate DNS hostnames using a wordlist

    > nmap -T4 -p 53 --script dns-brute google.com
    Use When: you want to enumerate DNS hostnames by brute forcing only POPULAR subdomain names
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

'''

onlineTools = '''Utilizing Online Resources
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DNS Dumpster
    > https://dnsdumpster.com
    Use when: you want a free domain research tool for DNS recon & research and find & lookup DNS records, without doing the commands above

HackerTarget
    > https://hackertarget.com
    Use When: you want to utilize open-source security tools found online for Network Testing, DNS queries, IP Address scanning and enumeration, and Web Tools

Whois
    > https://who.is
    Use When: you want to find information on the owner, nameserver, registrar, etc. of a domain name

Wayback Machine
    > https://archive.org/web/
    Use When: you want to view older versions of a website, see content that’ve changed, troubleshoot your own site, and even view content that no longer “exists” on the web
'''

def single_req(type):
    try:
        answer = dns.resolver.resolve(link,type,raise_on_no_answer=False)
        if answer.rrset is not None:
            print("\n" + type + " record")
            print("-"*30)
            print(answer.rrset + "\n")
    except dns.resolver.NXDOMAIN:
        print("\nDomain does not exist \n")
    except:
        pass  

def subdomain_scan():
    inp_list = input("Use a different wordlist? (y/n)").lower()
    

    if inp_list == "y":
        list = input("Enter wordlist file: ")           
        sub_list = open(list).read()
        subdomain_array = sub_list.splitlines()
    else:
        subdomain_array = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4', 'mail3', 'help', 'blogs', 'helpdesk', 'web1', 'home', 'library', 'ftp2', 'ntp', 'monitor', 'login', 'service', 'correo', 'www4', 'moodle', 'it', 'gateway', 'gw', 'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web2', 'ns5', 'upload', 'nagios', 'smtp2', 'online', 'ad', 'survey', 'data', 'radio', 'extranet', 'test2', 'mssql', 'dns3', 'jobs', 'services', 'panel', 'irc', 'hosting', 'cloud', 'de', 'gmail', 's', 'bbs', 'cs', 'ww', 'mrtg', 'git', 'image', 'members', 'poczta', 's1', 'meet', 'preview', 'fr', 'cloudflare-resolve-to', 'dev2', 'photo', 'jabber', 'legacy', 'go', 'es', 'ssh', 'redmine', 'partner', 'vps', 'server1', 'sv', 'ns6', 'webmail2', 'av', 'community', 'cacti', 'time', 'sftp', 'lib', 'facebook', 'www5', 'smtp1', 'feeds', 'w', 'games', 'ts', 'alumni', 'dl', 's2', 'phpmyadmin', 'archive', 'cn', 'tools', 'stream', 'projects', 'elearning', 'im', 'iphone', 'control', 'voip', 'test1', 'ws', 'rss', 'sp', 'wwww', 'vpn2', 'jira', 'list', 'connect', 'gallery', 'billing', 'mailer', 'update', 'pda', 'game', 'ns0', 'testing', 'sandbox', 'job', 'events', 'dialin', 'ml', 'fb', 'videos', 'music', 'a', 'partners', 'mailhost', 'downloads', 'reports', 'ca', 'router', 'speedtest', 'local', 'training', 'edu', 'bugs', 'manage', 's3', 'status', 'host2', 'ww2', 'marketing', 'conference', 'content', 'network-ip', 'broadcast-ip', 'english', 'catalog', 'msoid', 'mailadmin', 'pay', 'access', 'streaming', 'project', 't', 'sso', 'alpha', 'photos', 'staff', 'e', 'auth', 'v2', 'web5', 'web3', 'mail4', 'devel', 'post', 'us', 'images2', 'master', 'rt', 'ftp1', 'qa', 'wp', 'dns4', 'www6', 'ru', 'student', 'w3', 'citrix', 'trac', 'doc', 'img2', 'css', 'mx3', 'adm', 'web4', 'hr', 'mailserver', 'travel', 'sharepoint', 'sport', 'member', 'bb', 'agenda', 'link', 'server2', 'vod', 'uk', 'fw', 'promo', 'vip', 'noc', 'design', 'temp', 'gate', 'ns7', 'file', 'ms', 'map', 'cache', 'painel', 'js', 'event', 'mailing', 'db1', 'c', 'auto', 'img1', 'vpn1', 'business', 'mirror', 'share', 'cdn2', 'site', 'maps', 'tickets', 'tracker', 'domains', 'club', 'images1', 'zimbra', 'cvs', 'b2b', 'oa', 'intra', 'zabbix', 'ns8', 'assets', 'main', 'spam', 'lms', 'social', 'faq', 'feedback', 'loopback', 'groups', 'm2', 'cas', 'loghost', 'xml', 'nl', 'research', 'art', 'munin', 'dev1', 'gis', 'sales', 'images3', 'report', 'google', 'idp', 'cisco', 'careers', 'seo', 'dc', 'lab', 'd', 'firewall', 'fs', 'eng', 'ann', 'mail01', 'mantis', 'v', 'affiliates', 'webconf', 'track', 'ticket', 'pm', 'db2', 'b', 'clients', 'tech', 'erp', 'monitoring', 'cdn1', 'images4', 'payment', 'origin', 'client', 'foto', 'domain', 'pt', 'pma', 'directory', 'cc', 'public', 'finance', 'ns11', 'test3', 'wordpress', 'corp', 'sslvpn', 'cal', 'mailman', 'book', 'ip', 'zeus', 'ns10', 'hermes', 'storage', 'free', 'static1', 'pbx', 'banner', 'mobil', 'kb', 'mail5', 'direct', 'ipfixe', 'wifi', 'development', 'board', 'ns01', 'st', 'reviews', 'radius', 'pro', 'atlas', 'links', 'in', 'oldmail', 'register', 's4', 'images6', 'static2', 'id', 'shopping', 'drupal', 'analytics', 'm1', 'images5', 'images7', 'img3', 'mx01', 'www7', 'redirect', 'sitebuilder', 'smtp3', 'adserver', 'net', 'user', 'forms', 'outlook', 'press', 'vc', 'health', 'work', 'mb', 'mm', 'f', 'pgsql', 'jp', 'sports', 'preprod', 'g', 'p', 'mdm', 'ar', 'lync', 'market', 'dbadmin', 'barracuda', 'affiliate', 'mars', 'users', 'images8', 'biblioteca', 'mc', 'ns12', 'math', 'ntp1', 'web01', 'software', 'pr', 'jupiter', 'labs', 'linux', 'sc', 'love', 'fax', 'php', 'lp', 'tracking', 'thumbs', 'up', 'tw', 'campus', 'reg', 'digital', 'demo2', 'da', 'tr', 'otrs', 'web6', 'ns02', 'mailgw', 'education', 'order', 'piwik', 'banners', 'rs', 'se', 'venus', 'internal', 'webservices', 'cm', 'whois', 'sync', 'lb', 'is', 'code', 'click', 'w2', 'bugzilla', 'virtual', 'origin-www', 'top', 'customer', 'pub', 'hotel', 'openx', 'log', 'uat', 'cdn3', 'images0', 'cgi', 'posta', 'reseller', 'soft', 'movie', 'mba', 'n', 'r', 'developer', 'nms', 'ns9', 'webcam', 'construtor', 'ebook', 'ftp3', 'join', 'dashboard', 'bi', 'wpad', 'admin2', 'agent', 'wm', 'books', 'joomla', 'hotels', 'ezproxy', 'ds', 'sa', 'katalog', 'team', 'emkt', 'antispam', 'adv', 'mercury', 'flash', 'myadmin', 'sklep', 'newsite', 'law', 'pl', 'ntp2', 'x', 'srv1', 'mp3', 'archives', 'proxy2', 'ps', 'pic', 'ir', 'orion', 'srv', 'mt', 'ocs', 'server3', 'meeting', 'v1', 'delta', 'titan', 'manager', 'subscribe', 'develop', 'wsus', 'oascentral', 'mobi', 'people', 'galleries', 'wwwtest', 'backoffice', 'sg', 'repo', 'soporte', 'www8', 'eu', 'ead', 'students', 'hq', 'awstats', 'ec', 'security', 'school', 'corporate', 'podcast', 'vote', 'conf', 'magento', 'mx4', 'webservice', 'tour', 's5', 'power', 'correio', 'mon', 'mobilemail', 'weather', 'international', 'prod', 'account', 'xx', 'pages', 'pgadmin', 'bfn2', 'webserver', 'www-test', 'maintenance', 'me', 'magazine', 'syslog', 'int', 'view', 'enews', 'ci', 'au', 'mis', 'dev3', 'pdf', 'mailgate', 'v3', 'ss', 'internet', 'host1', 'smtp01', 'journal', 'wireless', 'opac', 'w1', 'signup', 'database', 'demo1', 'br', 'android', 'career', 'listserv', 'bt', 'spb', 'cam', 'contacts', 'webtest', 'resources', '1', 'life', 'mail6', 'transfer', 'app1', 'confluence', 'controlpanel', 'secure2', 'puppet', 'classifieds', 'tunet', 'edge', 'biz', 'host3', 'red', 'newmail', 'mx02', 'sb', 'physics', 'ap', 'epaper', 'sts', 'proxy1', 'ww1', 'stg', 'sd', 'science', 'star', 'www9', 'phoenix', 'pluto', 'webdav', 'booking', 'eshop', 'edit', 'panelstats', 'xmpp', 'food', 'cert', 'adfs', 'mail02', 'cat', 'edm', 'vcenter', 'mysql2', 'sun', 'phone', 'surveys', 'smart', 'system', 'twitter', 'updates', 'webmail1', 'logs', 'sitedefender', 'as', 'cbf1', 'sugar', 'contact', 'vm', 'ipad', 'traffic', 'dm', 'saturn', 'bo', 'network', 'ac', 'ns13', 'webdev', 'libguides', 'asp', 'tm', 'core', 'mms', 'abc', 'scripts', 'fm', 'sm', 'test4', 'nas', 'newsletters', 'rsc', 'cluster', 'learn', 'panelstatsmail', 'lb1', 'usa', 'apollo', 'pre', 'terminal', 'l', 'tc', 'movies', 'sh', 'fms', 'dms', 'z', 'base', 'jwc', 'gs', 'kvm', 'bfn1', 'card', 'web02', 'lg', 'editor', 'metrics', 'feed', 'repository', 'asterisk', 'sns', 'global', 'counter', 'ch', 'sistemas', 'pc', 'china', 'u', 'payments', 'ma', 'pics', 'www10', 'e-learning', 'auction', 'hub', 'sf', 'cbf8', 'forum2', 'ns14', 'app2', 'passport', 'hd', 'talk', 'ex', 'debian', 'ct', 'rc', '2012', 'imap4', 'blog2', 'ce', 'sk', 'relay2', 'green', 'print', 'geo', 'multimedia', 'iptv', 'backup2', 'webapps', 'audio', 'ro', 'smtp4', 'pg', 'ldap2', 'backend', 'profile', 'oldwww', 'drive', 'bill', 'listas', 'orders', 'win', 'mag', 'apply', 'bounce', 'mta', 'hp', 'suporte', 'dir', 'pa', 'sys', 'mx0', 'ems', 'antivirus', 'web8', 'inside', 'play', 'nic', 'welcome', 'premium', 'exam', 'sub', 'cz', 'omega', 'boutique', 'pp', 'management', 'planet', 'ww3', 'orange', 'c1', 'zzb', 'form', 'ecommerce', 'tmp', 'plus', 'openvpn', 'fw1', 'hk', 'owncloud', 'history', 'clientes', 'srv2', 'img4', 'open', 'registration', 'mp', 'blackboard', 'fc', 'static3', 'server4', 's6', 'ecard', 'dspace', 'dns01', 'md', 'mcp', 'ares', 'spf', 'kms', 'intranet2', 'accounts', 'webapp', 'ask', 'rd', 'www-dev', 'gw2', 'mall', 'bg', 'teste', 'ldap1', 'real', 'm3', 'wave', 'movil', 'portal2', 'kids', 'gw1', 'ra', 'tienda', 'private', 'po', '2013', 'cdn4', 'gps', 'km', 'ent', 'tt', 'ns21', 'at', 'athena', 'cbf2', 'webmail3', 'mob', 'matrix', 'ns15', 'send', 'lb2', 'pos', '2', 'cl', 'renew', 'admissions', 'am', 'beta2', 'gamma', 'mx5', 'portfolio', 'contest', 'box', 'mg', 'wwwold', 'neptune', 'mac', 'pms', 'traveler', 'media2', 'studio', 'sw', 'imp', 'bs', 'alfa', 'cbf4', 'servicedesk', 'wmail', 'video2', 'switch', 'sam', 'sky', 'ee', 'widget', 'reklama', 'msn', 'paris', 'tms', 'th', 'vega', 'trade', 'intern', 'ext', 'oldsite', 'learning', 'group', 'f1', 'ns22', 'ns20', 'demo3', 'bm', 'dom', 'pe', 'annuaire', 'portail', 'graphics', 'iris', 'one', 'robot', 'ams', 's7', 'foro', 'gaia', 'vpn3']

    invalid_subdoms = []

    subdomain_store = []
    for subdoms in subdomain_array:
        try:
            ip_value = dns.resolver.resolve(f'{subdoms}.{link}', 'A')
            if ip_value:
                subdomain_store.append(f'{subdoms}.{link}')
                if f"{subdoms}.{link}" in subdomain_store:
                    print(f'{subdoms}.{link} valid')
                else:
                    pass
        except:
            invalid_subdoms.append(f'{subdoms}')
            pass
    
    print("\n\n")
    print("INVALID SUBDOMAINS: ")
    for invalid_subdom in invalid_subdoms:
        print(f'{invalid_subdom}.{link}')

def get_domname(IP):
    addrs = dns.reversename.from_address(IP)
    try:
        print("Domain name of " + str(IP) + " is " + str(dns.resolver.resolve(addrs,"PTR")[0]))
    except:
        print("Does not exist")

def dns_zone_xfer(address):
    ns_servers = []
    try:
        ns_answer = dns.resolver.resolve(address, 'NS')
        if ns_answer.rrset is not None:
            for server in ns_answer:
                print("[*] Found NS: {}".format(server))
                ip_answer = dns.resolver.resolve(server.target, 'A')
                for ip in ip_answer:
                    print("[*] IP for {} is {}".format(server, ip))
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ip), address))
                        for host in zone:
                            print("[*] Found Host: {}".format(host))
                    except Exception as e:
                        print("[*] NS {} refused zone transfer!".format(server))
                        continue
    except dns.resolver.NXDOMAIN:
        print("\nDomain does not exist \n")
    except:
        pass

def dnsCheatSheet():
    print(header)
    print(dig)
    print(otherTools)
    print(onlineTools)


end = True

while end:

    print("1 - DNS Enumeration")
    print("2 - Subdomain Enumeration")
    print("3 - Reverse DNS Lookup")
    print("4 - DNS Zone Transfer")
    print("5 - DNS Cheat Sheet")
    print("6 - EXIT")

    action = int(input("Instruction: "))
    
    if action == 1:
        link = input("Enter Domain: ")
        req_type = input("Record Type: ").lower()

        if req_type == "a":
            record_types = 'A'
            single_req(record_types)
        elif req_type == "aaaa":
            record_types = 'AAAA'
            single_req(record_types)
        elif req_type == "mx":
            record_types = 'MX'
            single_req(record_types)
        elif req_type == "ns":
            record_types = 'NS'
            single_req(record_types)
        elif req_type == "cname":
            record_types = 'CNAME'
            single_req(record_types)
        elif req_type == "soa":
            record_types = 'SOA'
            single_req(record_types)
        elif req_type == "txt":
            record_types = 'TXT'  
            single_req(record_types) 
        elif req_type == "all":
            record_types = ['A','AAAA','MX','NS','CNAME','SOA','TXT']
            A = []
            AAAA = []
            MX = []
            NS = []
            CNAME = []
            SOA = []
            TXT = []

            for type in record_types: 
                try:
                    answer = dns.resolver.resolve(link,type,raise_on_no_answer=False)
                    for server in answer:
                        if type == "A":
                            A.append(server.to_text())
                        if type == "AAAA":
                            AAAA.append(server.to_text())
                        if type == "MX":
                            MX.append(server.to_text())
                        if type == "NS":
                            NS.append(server.to_text())
                        if type == "CNAME":
                            CNAME.append(server.to_text())
                        if type == "SOA":
                            SOA.append(server.to_text())
                        if type == "TXT":
                            TXT.append(server.to_text())

                    if answer.rrset is not None:
                        print(type + " record")
                        print("-"*30)
                        print(answer.rrset)
                        print("\n")
                except dns.resolver.NXDOMAIN:
                    print("\nDomain does not exist \n")
                except:
                    pass  
            
            print("\n")
            if len(A) > 0:
                print(f"A: {len(A)} Records Found!")
            if len(AAAA) > 0:
                print(f"AAAA: {len(AAAA)} Records Found!")
            if len(MX) > 0:
                print(f"MX: {len(MX)} Records Found!")
            if len(NS) > 0:
                print(f"NS: {len(NS)} Records Found!")
            if len(CNAME) > 0:
                print(f"CNAME: {len(CNAME)} Records Found!")
            if len(SOA) > 0:
                print(f"SOA: {len(SOA)} Records Found!")
            if len(TXT) > 0:
                print(f"TXT: {len(TXT)} Records Found!")
            print("\n")

    elif action == 2:
        link = input("Enter Domain: ")
        subdomain_scan()
        print("-"*30)
        print("\n")
    elif action == 3:
        get_domname(input("Enter IP: "))
        print("-"*30)
        print("\n")
    elif action == 4:
        link = input("Enter Domain: ")
        dns_zone_xfer(link)
    elif action == 5:
        print(header)
        print(dig)
        print(otherTools)
        print(onlineTools)

        save = (input('save? (y/n)\n'))
        
        if save.lower() == 'y':
            f = open("cheatsheet.txt", "w")
            f.write(header)
            f.close()

            f = open("cheatsheet.txt", "a")
            f.write(dig)
            f.write(otherTools)
            f.write(onlineTools)
            f.close()

            print('Successfully wrote to \'cheatsheet.txt\'')
            
    elif action == 6:
        end = False
    else:
        print("Enter valid record type")
