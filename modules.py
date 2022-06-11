import pytz
import pydig
import whois


class bcolors:
    OK = '\033[92m'  # GREEN
    WARNING = '\033[93m'  # YELLOW
    FAIL = '\033[91m'  # RED
    RESET = '\033[0m'  # RESET COLOR


def get_data(domain):
    whois_raw_data = whois.query(domain)
    if whois_raw_data is None:
        print(bcolors.FAIL, 'This domain is not registered.')
    else:
        print('\033[1;32mDomain name:\t', bcolors.RESET, whois_raw_data.name)
        print('\033[1;32mRegistrar:\t', bcolors.RESET, whois_raw_data.registrar)
        print('\033[1;32mNameservers:')
        for i in whois_raw_data.name_servers:
            print('\t', bcolors.RESET, i)
        creation_date = whois_raw_data.creation_date
        print('\033[1;32mRegistered at:\t', bcolors.RESET, creation_date.ctime(), '\033[1;32m\tBy Kyiv time:\t',
              bcolors.RESET, creation_date.astimezone(pytz.timezone('Europe/Kiev')))
        print('\033[1;32mUpdated at:\t', bcolors.RESET, whois_raw_data.last_updated.ctime(), '\t')
        print('\033[1;32mExpires at:\t', bcolors.RESET, whois_raw_data.expiration_date.ctime(), '\t')
        print('\033[1;32mDomain statuses:')
        for i in whois_raw_data.statuses:
            print('\t', bcolors.RESET, i)
        get_dns_data(whois_raw_data)


def get_dns_data(whois_raw_data):
    if 'dns1.namecheaphosting.com' != whois_raw_data.name_servers[0]:
        print('\033[1;32mDNS lookup information:\t', bcolors.WARNING, 'Warning! Domain not using Web Hosting DNS.',
              bcolors.OK)
        a_query = pydig.query(str(whois_raw_data.name), 'A')
        for i in a_query:
            print('\t\033[1;32mA\t', bcolors.RESET, i)
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
        a_query = pydig.query(str(whois_raw_data.name), 'A')
        for i in a_query:
            print('\t\033[1;32mA\t', bcolors.RESET, i)
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
