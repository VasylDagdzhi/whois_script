import pytz
import pydig
import whois
import validators
import tldextract


class bcolors:
    OK = '\033[92m'  # GREEN
    WARNING = '\033[93m'  # YELLOW
    FAIL = '\033[91m'  # RED
    PURPLE = '\033[35m'  # PURPLE
    RESET = '\033[0m'  # RESET COLOR
    WHITE = '\033[1;37m'  # WHITE COLOR


def get_domain_statuses(whois_raw_data):
    status = True;
    print('\033[1;32mDomain statuses:')
    for i in whois_raw_data.statuses:
        split_str = i.split(" ")
        tabulator1 = '\t'
        tabulator2 = '\t\t'
        tabulator3 = '\t\t\t'
        x = len(str(split_str[0]))
        y = float(24 / x )
        if y <= 1:
            tabulator = tabulator1
        elif 1 < y < 2.2:
            tabulator = tabulator2
        elif 2.2 < y:
            tabulator = tabulator3
        if "clientHold" == split_str[0]:
            print('\t', bcolors.FAIL, split_str[0], tabulator, split_str[1])
            status = False
        elif "serverHold" == split_str[0]:
            print('\t', bcolors.FAIL, split_str[0], tabulator, split_str[1])
        elif "pendingDelete" == split_str[0]:
            print('\t', bcolors.WARNING, split_str[0], tabulator, split_str[1])
            status = False
        elif "redemptionPeriod" == split_str[0]:
            print('\t', bcolors.PURPLE, split_str[0], tabulator, split_str[1])
            status = False
        else:
            print('\t', bcolors.RESET, split_str[0], tabulator, split_str[1])
        return status


def get_data(domain):
    whois_raw_data = whois.query(domain)
    if whois_raw_data is None:
        print(bcolors.FAIL, 'This domain is not registered.')
    else:
        print('\033[1;32mDomain name:\t', bcolors.WHITE, whois_raw_data.name)
        print('\033[1;32mRegistrar:\t', bcolors.WHITE, whois_raw_data.registrar)
        print('\033[1;32mNameservers:')
        for i in whois_raw_data.name_servers:
            print('\t', bcolors.WHITE, i)
        creation_date = whois_raw_data.creation_date
        print('\033[1;32mRegistered at:\t', bcolors.RESET, creation_date.ctime(), '\033[1;32m\tBy Kyiv time:\t',
              bcolors.RESET, creation_date.astimezone(pytz.timezone('Europe/Kiev')))
        print('\033[1;32mUpdated at:\t', bcolors.RESET, whois_raw_data.last_updated.ctime(), '\t')
        print('\033[1;32mExpires at:\t', bcolors.RESET, whois_raw_data.expiration_date.ctime(), '\t')
        status = get_domain_statuses(whois_raw_data)
        if status:
            get_dns_data(whois_raw_data)
        else:
            print(bcolors.FAIL, "This domain is not active.", bcolors.RESET)


def get_dns_data(whois_raw_data):
    if 'dns1.namecheaphosting.com' != whois_raw_data.name_servers[0]:
        print('\033[1;32mDNS lookup information:\t', bcolors.WARNING, 'Warning! Domain not using Web Hosting DNS.',
              bcolors.OK)
        a_query = pydig.query(str(whois_raw_data.name), 'A')
        for i in a_query:
            print('\t\033[1;32mA\t', bcolors.RESET, i)
        mx_query = pydig.query(str(whois_raw_data.name), 'MX')
        for i in mx_query:
            print('\033[1;32m\tSPF\t', bcolors.WHITE, i)
        txt_query = pydig.query(str(whois_raw_data.name), 'TXT')
        for i in txt_query:
            if 'v=spf' in i:
                print('\033[1;32m\tSPF\t', bcolors.RESET, i)
            else:
                print('\033[1;32m\tTXT\t', bcolors.RESET, i)
        dkim = pydig.query('default._domainkey.' + str(whois_raw_data.name), 'TXT')
        for i in dkim:
            if 'v=DKIM' in i:
                print('\033[1;32m\tDKIM\t', bcolors.RESET, i)
    else:
        ns1a = str(pydig.query(whois_raw_data.name_servers[0], 'A'))
        ns2a = str(pydig.query(whois_raw_data.name_servers[1], 'A'))
        resolver = pydig.Resolver(
            nameservers=[
                whois_raw_data.name_servers[0].__str__(),
                whois_raw_data.name_servers[1].__str__()
            ],
            additional_args=[
                '+time=10'
            ]
        )
        query = resolver.query(str(whois_raw_data.name), 'A')
        print('\033[1;32mDNS lookup information:\t')
        a_query = resolver.query(str(whois_raw_data.name), 'A')
        for i in a_query:
            print('\t\033[1;32mA\t', bcolors.RESET, i)
        mx_query = resolver.query(str(whois_raw_data.name), 'MX')
        for i in mx_query:
            print('\033[1;32m\tMX\t', bcolors.WHITE, i)
        txt_query = resolver.query(str(whois_raw_data.name), 'TXT')
        for i in txt_query:
            if 'v=spf' in i:
                print('\033[1;32m\tSPF\t', bcolors.RESET, i)
            else:
                print('\033[1;32m\tTXT\t', bcolors.RESET, i)
        dkim = resolver.query('default._domainkey.' + str(whois_raw_data.name), 'TXT')
        for i in dkim:
            if 'v=DKIM' in i:
                print('\033[1;32m\tDKIM\t', bcolors.RESET, i)


def begin(entered_domain):
    # validate the input string to be a domain or not
    if validators.domain(entered_domain):
        if tldextract.extract(entered_domain).suffix not in whois.validTlds():
            print(bcolors.FAIL, 'Unfortunately, "{0}"\tis an unsupported TLD'.format(str(
                tldextract.extract(entered_domain).suffix)))
        # check if the entered domain's TLD is in the list of supported ones to parse data
        else:
            # call the function that parses the required fields and shows them in a comfortable way
            get_data(entered_domain)
    else:
        print(bcolors.FAIL, 'You have input a non valid domain name.')
