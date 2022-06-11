# This is a Whois parser script created for Namecheap Domain team
# Inspired by Kate Shevchenko
# Created by Vasiliy Dagdzhi

# module definitions
import validators
import whois
import tldextract
import pytz


def get_data(domain):
    whois_raw_data = whois.query(domain)
    print("\033[1;32mDomain name:\t", whois_raw_data.name)
    print("Registrar:\t", whois_raw_data.registrar)
    print("Nameservers:")
    for i in whois_raw_data.name_servers:
        print("\t", i)
    creation_date = whois_raw_data.creation_date
    print('Registered at:\t', creation_date.ctime(), "\t( By Kyiv time:\t", creation_date.astimezone(pytz.timezone(
        'Europe/Kiev')), " )")
    print('Updated at:\t', whois_raw_data.last_updated.ctime(), "\t")
    print('Expires at:\t', whois_raw_data.expiration_date.ctime(), "\t")
    print("Domain statuses:")
    for i in whois_raw_data.statuses:
        print("\t", i)


# entered_domain = "ljnero.us"
entered_domain = input("Enter the domain name: ")

# validate the input string to be a domain or not
if validators.domain(entered_domain):
    # check if the entered domain's TLD is in the list of supported ones to parse data
    if tldextract.extract(entered_domain).suffix in whois.validTlds():
        # call the function that parses the required fields and shows them in a comfortable way
        get_data(entered_domain)
    else:
        print('Unfortunately, "{0}"\tis an unsupported TLD'.format(str(tldextract.extract(entered_domain).suffix)))
else:
    print('You have input a non valid domain name.')

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
