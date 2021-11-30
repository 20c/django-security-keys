These settings should be added to your django project settings.

- `WEBAUTHN_RP_ID`: rp id to use for webauthn, in most cases this would be your hostname (e.g., `localhost` or `www.example.com`)
- `WEBAUTHN_ORIGIN`: http origin to use for webauthn, this should be a url and match the host that originates the registration and authentication requests (e.g., `https://localhost` or `https://www.example.com` or `https://www.example.com:1234`)

There are no default values for these as they are crucial for operation.
