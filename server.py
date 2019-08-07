#!/usr/bin/env python3

import ldap3
from aiohttp import web

import os
import sys
import base64
import logging

log = logging.getLogger()
logging.basicConfig(level=logging.INFO)


class SendChallenge(Exception):
    pass

class ConfigError(Exception):
    pass


def index(request):
    try:
        config = getconfig(request.headers)
        username, dn = authenticate_user(request, config)
    except SendChallenge:
        headers = {
            'WWW-Authenticate': 'Basic realm="%s"' % config['X-Ldap-Realm'],
            'Cache-Control': 'no-cache'
        }
        return web.Response(status=401, headers=headers)
    except ConfigError as error:
        log.error(error)
        return web.Response(status=500, text='LDAP authentication error')

    headers = {
        'AUTHENTICATED_USER': username,
        'AUTHENTICATED_DN': dn,
    }
    return web.Response(status=200, headers=headers, text='')


def authenticate_user(request, config):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.lower().startswith('basic '):
        raise SendChallenge()

    auth_data = auth_header.split(None, 1)[-1]
    auth_data = base64.b64decode(auth_data).decode('ascii')
    username, password = auth_data.split(':', 1)

    if '%s' in config['X-Ldap-BindDN']:
        binddn = config['X-Ldap-BindDN'] % username
        log.debug('Performing anonymous bind with "%s"', binddn)
        conn = connect_ldap(config['X-Ldap-URL'], binddn, password, auto_bind=False)
        if not conn.bind():
            log.error('Anonymous bind error for user "%s": %s', binddn, conn.result)
            raise SendChallenge()

        return username, binddn

    else:
        # TODO: Not implemented yet.
        conn = connect_ldap(config['X-Ldap-URL'], config['X-Ldap-BindDN'], config['X-Ldap-BindPW'])
        exists = conn.search(config['X-BaseDN'], '(objectClass=*)', ldap3.SUBTREE, attributes=['objectClass'])

        if not exists:
            raise SendChallenge()


def connect_ldap(ldap_host, bind_dn=None, bind_passwd=None, auto_bind=True):
    server = ldap3.Server(ldap_host, use_ssl=False)
    conn = ldap3.Connection(server, user=bind_dn, password=bind_passwd, auto_bind=auto_bind)
    return conn


def getconfig(headers):
    required = 0x1

    spec = {
        'X-Ldap-Realm':  ('NGINX_LDAP_REALM', 'Restricted'),
        'X-Ldap-URL':    ('NGINX_LDAP_URL',    required),
        'X-Ldap-BaseDN': ('NGINX_LDAP_BASEDN', None),
        'X-Ldap-BindDN': ('NGINX_LDAP_BINDDN', None),
        'X-Ldap-BindPW': ('NGINX_LDAP_BINDPW', None),
    }

    config = {}
    for header_key, value in spec.items():
        env_key, default = value
        default = os.environ.get(env_key, default)
        config[header_key] = headers.get(header_key, default)

    # Validate required values.
    for key, value in config.items():
        if value is required:
            env_key = spec[key][0]
            raise ConfigError(f'Missing "{key}" header or "{env_key}" environment variable')

    if ('%s' not in config['X-Ldap-BindDN']) and (config['X-Ldap-BindPW'] is None):
        raise ConfigError('Bind DN specified without bind password')

    return config

def main():
    app = web.Application()
    app.add_routes([web.get('/', index)])

    bind_addr = sys.argv[1]
    if bind_addr.startswith('unix:'):
        run_kwarg = {'path': bind_addr.split('unix:', 1)[-1]}
    else:
        host, port = bind_addr.split(':', 1)
        run_kwarg = {'host': host, 'port': int(port)}

    web.run_app(app, **run_kwarg, access_log=None)

if __name__ == '__main__':
    main()
