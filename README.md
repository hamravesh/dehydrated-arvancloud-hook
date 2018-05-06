# ArvanCloud hook for `dehydrated`

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [dehydrated](https://github.com/lukas2511/dehydrated) (previously known as `letsencrypt.sh`) that allows you to use [ArvanCloud](https://arvancloud.com/) DNS records to respond to `dns-01` challenges. Requires Python and your ArvanCloud account e-mail and password being in the environment.

## Installation

```
$ cd ~
$ git clone https://github.com/lukas2511/dehydrated
$ cd dehydrated
$ mkdir hooks
$ git clone https://github.com/hamravesh/dehydrated-arvancloud-hook.git hooks/arvancloud
```

If you are using Python 3:
```
$ pip install -r hooks/arvancloud/requirements.txt
```

Otherwise, if you are using Python 2 (make sure to also check the [urllib3 documentation](http://urllib3.readthedocs.org/en/latest/security.html#installing-urllib3-with-sni-support-and-certificates) for possible caveats):

```
$ pip install -r hooks/arvancloud/requirements-python-2.txt
```


## Configuration

Your account's ArvanCloud email and password are expected to be in the environment, so make sure to:

```
$ export ARVAN_EMAIL='user@example.com'
$ export ARVAN_PASSWORD='your-password'
```

Optionally, you can specify the DNS servers to be used for propagation checking via the `ARVAN_DNS_SERVERS` environment variable (props [bennettp123](https://github.com/bennettp123)):

```
$ export ARVAN_DNS_SERVERS='8.8.8.8 8.8.4.4'
```

If you want more information about what is going on while the hook is running:

```
$ export ARVAN_DEBUG='true'
```

Alternatively, these statements can be placed in `dehydrated/config`, which is automatically sourced by `dehydrated` on startup:

```
echo "export ARVAN_EMAIL=user@example.com" >> config
echo "export ARVAN_KEY=your-password" >> config
echo "export ARVAN_DEBUG=true" >> config
```




## Usage

```
$ ./dehydrated -c -d example.com -t dns-01 -k 'hooks/arvancloud/hook.py'
#
# !! WARNING !! No main config file found, using default config!
#
Processing example.com
 + Signing domains...
 + Creating new directory /home/user/dehydrated/certs/example.com ...
 + Generating private key...
 + Generating signing request...
 + Requesting challenge for example.com...
 + ArvanCloud hook executing: deploy_challenge
 + DNS not propagated, waiting 30s...
 + DNS not propagated, waiting 30s...
 + Responding to challenge for example.com...
 + ArvanCloud hook executing: clean_challenge
 + Challenge is valid!
 + Requesting certificate...
 + Checking certificate...
 + Done!
 + Creating fullchain.pem...
 + ArvanCloud hook executing: deploy_cert
 + ssl_certificate: /home/user/dehydrated/certs/example.com/fullchain.pem
 + ssl_certificate_key: /home/user/dehydrated/certs/example.com/privkey.pem
 + Done!
```

