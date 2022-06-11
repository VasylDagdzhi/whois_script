# This is a Whois Domain parser script created for Namecheap Domain team
# Inspired by Kate Shevchenko
# Created by Vasiliy Dagdzhi

# module definitions
import tldextract
import validators
import whois
import modules


class bcolors:
    OK = '\033[92m'  # GREEN
    WARNING = '\033[93m'  # YELLOW
    FAIL = '\033[91m'  # RED
    RESET = '\033[0m'  # RESET COLOR


entered_domain = 'ljnero.us'
# entered_domain = input('Enter the domain name: ')

# validate the input string to be a domain or not
if validators.domain(entered_domain):
    if tldextract.extract(entered_domain).suffix not in whois.validTlds():
        print(bcolors.FAIL, 'Unfortunately, "{0}"\tis an unsupported TLD'.format(str(
            tldextract.extract(entered_domain).suffix)))
    # check if the entered domain's TLD is in the list of supported ones to parse data
    else:
        # call the function that parses the required fields and shows them in a comfortable way
        modules.get_data(entered_domain)
else:
    print(bcolors.FAIL, 'You have input a non valid domain name.')

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
