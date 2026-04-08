# ACME-nostate
A stateless DNS-PERSIST-01 ACME client in different languages with cross-compatibility, making it possible to easily request certificates across different platforms.

# ACME.pl usage:

Requirements: Net::ACME2, Net::ACME2::LetsEncrypt, Digest::SHA, Crypt::Perl::ECDSA, Crypt::Perl::ECDSA::Parse, Crypt::Perl::PKCS10, Crypt::PK::ECC

Generate certificate

./ACME.pl [secret password] [file to write certificate to] [domain1] [domain2] [domain3] and so on...

Export private key

./ACME.pl [secret password] [file to write private key to] export

Get DNS-PERSIST-01 record

./ACME.pl [secret password]

# ACME.html usage:

Just start it in web browser.

Limitations: The domain field only supports up to 42 characters which fits 3-4 domains. This is a limitation due to the ASN1 structure in the CSR getting too fat otherwise and the handling of the 0x81 lengths becomes a bit troublesome.
I will propably fix it in the future.

Advantages: The client is totally client-side and does ONLY talk to lets encrypt server, meaning you do not have to trust any server.

# Key generation on a server - run the following command in console (can be done offline without network connection if you want and does not need root):

Certificate private key:

echo -n "[secret password]" | openssl dgst -sha384 -binary | xxd -p -c 48 | xargs -I {} printf "303e0201010430{}a00706052b81040022" | xxd -r -p | openssl ec -inform DER -conv_form uncompressed -out private_key.pem

Account private key (for import in other ACME client):

echo -n "[secret password]-" | openssl dgst -sha384 -binary | xxd -p -c 48 | xargs -I {} printf "303e0201010430{}a00706052b81040022" | xxd -r -p | openssl ec -inform DER -conv_form uncompressed -out private_key.pem

# Limitations (any changes outside of these limitations will NOT be accepted)

- Does ONLY support DNS-PERSIST-01 - this to make the client really portable.
- Does ONLY support secp384r1 keys - this to make stateless key generation possible.
- Does ONLY support wildcard generation - this to make code easier.
- Does NOT support ARI or similiar protocols

- For now: Does ONLY support staging - this will be updated once Let's Encrypt release DNS-PERSIST-01

# Use cases

You can set up the DNS-PERSIST-01 record on a DNS server, and then you can call your friend on the other side of the globe, tell him your password, and then he can generate certificates.

You can "pre-provision" a server with private keys and then use the same password to generate the certificate

You can make a read-only "live media" server, that only requires the password at startup, and it will generate all private keys and fetch certificates automatically.

No risk of losing private key - as long as you remember your password.
