# Summary

LDAP authentication for NGINX using
[auth_request](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html#auth_request)
and a Python helper daemon. This project is similar to the [reference
implementation](https://github.com/nginxinc/nginx-ldap-auth) provided by NGINX,
but much simpler.

# Example usage

1) The `server.py` daemon has two external dependencies: `ldap3` and `aiohttp`.
   Install them with pip or with your OS package manager. For example:

   ```
   python3 -m pip install aiohttp ldap3
   ```

2) Start `server.py` any way you like. For example, with a systemd service unit:

   **`/etc/systemd/system/nginx-ldap-auth.service:`**

   ```ini
   [Unit]
   Description=Nginx LDAP Authentication Helper
   After=network.target

   [Service]
   User=nginx-ldap-auth
   RuntimeDirectory=nginx-ldap-auth
   UMask=0002
   ExecStart=/usr/bin/python3 server.py unix:///run/nginx-ldap-auth/server.sock

   [Install]
   WantedBy=multi-user.target
   ```

   ```
   systemctl enable nginx-ldap-auth
   systemctl start nginx-ldap-auth
   ```

3) Configure NGINX:

   ```nginx
   server {
       listen 80;
       server_name ...;

       location = /auth-proxy {
           internal;
           proxy_pass http://unix:/run/nginx-ldap-auth/server.sock:/;

           proxy_pass_request_body off;
           proxy_set_header Content-Length "";

           # With the following configuration, the helper program will attempt
           # to bind to ldap.example.com with the user-provided username and
           # password. The username is interpolated in the X-Ldap-BindDN header.
           proxy_set_header X-Ldap-URL     "ldap.example.com";
           proxy_set_header X-Ldap-Realm   "Protected";
           proxy_set_header X-Ldap-BaseDN  "dc=example,dc=com";
           proxy_set_header X-Ldap-BindDN  "uid=%s,ou=users,dc=example,dc=com";
       }

       location / {
           auth_request /auth-proxy;

           # Upon success, the authenticated username and their DN are made
           # available as variables.
           auth_request_set $auth_user $upstream_http_AUTHENTICATED_USER;
           auth_request_set $auth_dn $upstream_http_AUTHENTICATED_DN;

           # These variables can be forwarded to the backend.
           proxy_set_header REMOTE_USER $auth_user;
           proxy_pass ...;
       }
   }
   ```
