#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from builtins import str

from future import standard_library
standard_library.install_aliases()

import dns.exception
import dns.resolver
import logging
import os
import requests
import sys
import time

from tld import get_tld

# Enable verified HTTPS requests on older Pythons
# http://urllib3.readthedocs.org/en/latest/security.html
if sys.version_info[0] == 2:
    try:
        requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()
    except AttributeError:
        # see https://github.com/certbot/certbot/issues/1883
        import urllib3.contrib.pyopenssl
        urllib3.contrib.pyopenssl.inject_into_urllib3()

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())

if os.environ.get('ARVAN_DEBUG'):
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

def get_auth_token():
    ARVAN_EMAIL = os.environ['ARVAN_EMAIL']
    ARVAN_PASSWORD = os.environ['ARVAN_PASSWORD']
    url = "https://accounts.arvancloud.com/api/1.0/auth/v/authenticate?cb=0"
    payload = {
        'user': ARVAN_EMAIL,
        'password': ARVAN_PASSWORD,
    }
    r = requests.post(url, headers={'content-type': 'application/json'}, json=payload)
    r.raise_for_status()
    data = r.json()['data']
    return "Bearer {0}".format(data['token'])

try:
    ARVAN_HEADERS = {
        'Authorization' : get_auth_token(),
        'Content-Type'  : 'application/json',
    }
except KeyError:
    logger.error(" + Unable to locate ArvanCloud credentials in environment!")
    sys.exit(1)

try:
    dns_servers = os.environ['ARVAN_DNS_SERVERS']
    dns_servers = dns_servers.split()
except KeyError:
    dns_servers = False


def _has_dns_propagated(name, token):
    try:
        if dns_servers:
            custom_resolver = dns.resolver.Resolver()
            custom_resolver.nameservers = dns_servers
            dns_response = custom_resolver.query(name, 'TXT')
        else:
            dns_response = dns.resolver.query(name, 'TXT')
            
        for rdata in dns_response:
            if token in [b.decode('utf-8') for b in rdata.strings]:
                return True
                
    except dns.exception.DNSException as e:
        logger.debug(" + {0}. Retrying query...".format(e))
        
    return False


def _get_zone_id(domain):
    tld = get_tld('http://' + domain)
    return tld


def _get_txt_record_id(zone_id, name, token):


    url = "https://api.arvancloud.com/cdn/1.0/domains/{0}/dns?cb=0".format(zone_id)
    r = requests.get(url, headers=ARVAN_HEADERS)
    r.raise_for_status()
    try:
        all = r.json()['data']
        record_id = [rec for rec in all if rec['type_id'] == 'TXT' and ('%s.%s' % (rec['name'], zone_id)) == name and rec['value'] == [token]][0]['id']
    except IndexError:
        logger.debug(" + Unable to locate record named {0}".format(name))
        return

    return record_id


def create_txt_record(args):

    domain, challenge, token = args
    logger.debug(' + Creating TXT record: {0} => {1}'.format(domain, token))
    logger.debug(' + Challenge: {0}'.format(challenge))
    zone_id = _get_zone_id(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)
    
    record_id = _get_txt_record_id(zone_id, name, token)
    if record_id:
        logger.debug(" + TXT record exists, skipping creation.")
        return
    
    url = "https://api.arvancloud.com/cdn/1.0/domains/{0}/dns?cb=0".format(zone_id)
    payload = {
      'type_id': 'TXT',
      'name': name,
      'value': [token],
      'ttl': '120',
      'cloud': 0,
      'circle': 'default',
    }
    r = requests.post(url, headers=ARVAN_HEADERS, json=payload)
    r.raise_for_status()
    record_id = r.json()['data']['id']
    logger.debug(" + TXT record created, ID: {0}".format(record_id))


def delete_txt_record(args):
    domain, token = args[0], args[2]
    if not domain:
        logger.info(" + http_request() error in letsencrypt.sh?")
        return

    zone_id = _get_zone_id(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)
    record_id = _get_txt_record_id(zone_id, name, token)

    if record_id:
        url = "https://api.arvancloud.com/cdn/1.0/domains/{0}/dns/{1}".format(zone_id, record_id)
        r = requests.delete(url, headers=ARVAN_HEADERS)
        r.raise_for_status()
        logger.debug(" + Deleted TXT {0}, ID {1}".format(name, record_id))
    else:
        logger.debug(" + No TXT {0} with token {1}".format(name, token))


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    logger.debug(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.debug(' + ssl_certificate_key: {0}'.format(privkey_pem))
    return


def unchanged_cert(args):
    return
    

def invalid_challenge(args):
    domain, result = args
    logger.debug(' + invalid_challenge for {0}'.format(domain))
    logger.debug(' + Full error: {0}'.format(result))
    return


def create_all_txt_records(args):
    X = 3
    for i in range(0, len(args), X):
        create_txt_record(args[i:i+X])
    # give it 10 seconds to settle down and avoid nxdomain caching
    logger.info(" + Settling down for 10s...")
    time.sleep(10)
    for i in range(0, len(args), X):
        domain, token = args[i], args[i+2]
        name = "{0}.{1}".format('_acme-challenge', domain)
        while(_has_dns_propagated(name, token) == False):
            logger.info(" + DNS not propagated, waiting 30s...")
            time.sleep(30)


def delete_all_txt_records(args):
    X = 3
    for i in range(0, len(args), X):
        delete_txt_record(args[i:i+X])

def startup_hook(args):
    return

def exit_hook(args):
    return


def main(argv):
    ops = {
        'deploy_challenge': create_all_txt_records,
        'clean_challenge' : delete_all_txt_records,
        'deploy_cert'     : deploy_cert,
        'unchanged_cert'  : unchanged_cert,
        'invalid_challenge': invalid_challenge,
        'startup_hook': startup_hook,
        'exit_hook': exit_hook
    }
    if argv[0] in ops:
        logger.info(" + ArvanCloud hook executing: {0}".format(argv[0]))
        ops[argv[0]](argv[1:])

if __name__ == '__main__':
    main(sys.argv[1:])
