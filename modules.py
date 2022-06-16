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
    tabulator = ""
    status = True
    if not whois_raw_data.statuses:
        print(bcolors.FAIL, "Domain status not available.", bcolors.RESET)
    else:
        print('\033[1;32mDomain statuses:')
        for i in whois_raw_data.statuses:
            split_str = i.split(" ")
            tabulators = ['\t', '\t\t', '\t\t\t']
            x = len(str(split_str[0]))
            y = float(24 / x)
            if y <= 1:
                tabulator = tabulators[0]
            elif 1 < y < 2.2:
                tabulator = tabulators[1]
            elif 2.2 < y:
                tabulator = tabulators[2]
            if "clientHold" == split_str[0]:
                if split_str[1]:
                    print('\t', bcolors.FAIL, split_str[0], tabulator, split_str[1])
                else:
                    print('\t', bcolors.FAIL, split_str[0])
                status = False
            elif "serverHold" == split_str[0]:
                if split_str[1]:
                    print('\t', bcolors.FAIL, split_str[0], tabulator, split_str[1])
                else:
                    print('\t', bcolors.FAIL, split_str[0])
            elif "pendingDelete" == split_str[0]:
                if split_str[1]:
                    print('\t', bcolors.WARNING, split_str[0], tabulator, split_str[1])
                else:
                    print('\t', bcolors.FAIL, split_str[0])
                status = False
            elif "redemptionPeriod" == split_str[0]:
                if split_str[1]:
                    print('\t', bcolors.PURPLE, split_str[0], tabulator, split_str[1])
                else:
                    print('\t', bcolors.FAIL, split_str[0])
                status = False
            else:
                if len(split_str) > 1:
                    print('\t', bcolors.WHITE, split_str[0], tabulator, split_str[1])
                else:
                    print('\t', bcolors.WHITE, split_str[0])
    return status


def get_whois_data(domain):
    whois_raw_data = whois.query(domain)
    if not whois_raw_data:
        print(bcolors.FAIL, 'This domain is not registered.')
    else:
        print('\033[1;32mDomain name:\t', bcolors.WHITE, whois_raw_data.name)
        if not whois_raw_data.registrar:
            print('\033[91mRegistrar data absent.')
        else:
            print('\033[1;32mRegistrar:\t', bcolors.WHITE, whois_raw_data.registrar)
        print('\033[1;32mNameservers:')
        for i in whois_raw_data.name_servers:
            print('\t', bcolors.WHITE, i)
        creation_date = whois_raw_data.creation_date
        if not creation_date:
            print("\033[91mCreation date not available.", bcolors.RESET)
        else:
            print('\033[1;32mRegistered at:\t', bcolors.WHITE, creation_date.ctime(), '\033[1;32m\tBy Kyiv time:\t',
                  bcolors.WHITE, creation_date.astimezone(pytz.timezone('Europe/Kiev')))
        updated_time = whois_raw_data.last_updated
        if not updated_time:
            print("\033[91mTime of the last update is not available.", bcolors.RESET)
        else:
            print('\033[1;32mUpdated at:\t', bcolors.WHITE, updated_time.ctime(), '\t')
        expiration_date = whois_raw_data.expiration_date
        if not expiration_date:
            print("\033[91mExpiration date is not available.", bcolors.RESET)
        else:
            print('\033[1;32mExpires at:\t', bcolors.WHITE, expiration_date.ctime(), '\t')
        status = get_domain_statuses(whois_raw_data)
        if status:
            get_dns_data(whois_raw_data)
        else:
            print(bcolors.FAIL, "This domain is not active.", bcolors.RESET)


def print_dns_records(resolver, whois_raw_data):
    a_query = resolver.query(str(whois_raw_data.name), 'A')
    for i in a_query:
        print('\t\033[1;32mA\t', bcolors.WHITE, i)
    mx_query = resolver.query(str(whois_raw_data.name), 'MX')
    mx_query.sort(reverse=True)
    for i in mx_query:
        print('\033[1;32m\tMX\t', bcolors.WHITE, i)
    txt_query = resolver.query(str(whois_raw_data.name), 'TXT')
    for i in txt_query:
        if 'v=spf' in i:
            print('\033[1;32m\tSPF\t', bcolors.WHITE, i)
        else:
            print('\033[1;32m\tTXT\t', bcolors.WHITE, i)
    dkim = resolver.query('default._domainkey.' + str(whois_raw_data.name), 'TXT')
    for i in dkim:
        if 'v=DKIM' in i:
            print('\033[1;32m\tDKIM\t', bcolors.WHITE, i)


def get_dns_data(whois_raw_data):
    if 'dns1.namecheaphosting.com' != whois_raw_data.name_servers[0]:
        print('\033[1;32mDNS lookup information:\t', bcolors.WARNING, 'Warning! Domain not using Web Hosting DNS.',
              bcolors.OK)
        print_dns_records(pydig.Resolver(), whois_raw_data)
    else:
        resolver = pydig.Resolver(
            nameservers=[
                whois_raw_data.name_servers[0].__str__(),
                whois_raw_data.name_servers[1].__str__()
            ],
            additional_args=[
                '+time=10'
            ]
        )
        print('\033[1;32mDNS lookup information:\t')
        print_dns_records(resolver, whois_raw_data)


def begin(entered_domain):
    # validate the input string to be a domain or not
    if validators.domain(entered_domain):
        if tldextract.extract(entered_domain).suffix not in whois.validTlds():
            print(bcolors.FAIL, 'Unfortunately, "{0}"\tis an unsupported TLD'.format(str(
                tldextract.extract(entered_domain).suffix)))
        # check if the entered domain's TLD is in the list of supported ones to parse data
        else:
            # call the function that parses the required fields and shows them in a comfortable way
            get_whois_data(entered_domain)
    else:
        print(bcolors.FAIL, 'You have input a non valid domain name.')
