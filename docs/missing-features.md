# Missing features

## Attestation

> Attestation is built-in to the FIDO and WebAuthn protocols, which enables each relying party to use a cryptographically verified chain of trust from the device’s manufacturer to choose which security keys to trust, or to be more skeptical of, based on their individual needs and concerns.

Attestation is currently not configurable and no fields exist in the schema to store any attestation information.

Up to this point all the projects that integrate `django-security-keys` have had no need for attestation information and the [webauthn best-practices guide](https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/Attestation.html) recommends to not verify device attestation unless there exists a well defined policy in the service for what to do with it and why, so it has not been prioritized.

> If a service does not have a specific need for attestation information, namely a well defined policy for what to do with it and why, it is not recommended to verify authenticator attestations.

Support for attestation is planned for the future, albeit no time frame can be given at this point. 
