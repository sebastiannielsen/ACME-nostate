#!/usr/bin/perl

use Net::ACME2;
use Net::ACME2::LetsEncrypt;
use Digest::SHA qw(sha384_hex);
use Crypt::PK::ECC;
use MIME::Base64 qw(encode_base64);

$inpass = $ARGV[0];
$flags = $ARGV[1];
@valmethods = ('', 'dns-persist-01', 'http-01');


if (length($inpass) < 1) {
print "Password cannot be blank. Use a secure password to prevent someone guessing your private key.\n";
exit;
}
$flags =~ s/[^12]//sgi;
$flags = substr($flags, 0, 1);

if (length($flags) < 1) {
print "Flags cannot be blank. Use 1 to use DNS-PERSIST-01, use 2 to use HTTP-01.\n";
exit;
}


$acctpassword = pack("H*", sha384_hex($inpass."-"));

$acct = Crypt::PK::ECC->new();
$acct->import_key_raw($acctpassword, "secp384r1");

if ($ARGV[3] eq "export") {
open(PEMFILE, ">".$ARGV[2]);
print PEMFILE $cert->export_key_pem('private');
close(PEMFILE);
print "Written private key to ".$ARGV[2]."\n";
exit;
}

$acme = Net::ACME2::LetsEncrypt->new( key => $acct->export_key_pem('private'), environment => 'staging');


if (($flags eq "2")&&(length($ARGV[3]) < 5)) {

$keytoken = Net::ACME2::AccountKey->new( $acct->export_key_pem('private') )->get_jwk_thumbprint();

printf <<'CONFIG', $keytoken, $keytoken, $keytoken;

Add one of these snippets to your webserver config (depending on which server you have):

Apache2 or LiteSpeed/OpenLiteSpeed:
-----------------------------------------------------
<Location "/.well-known/acme-challenge/">
    RewriteEngine On
    RewriteRule "\/([-_a-zA-Z0-9]+)$" "\/$1" [E=challenge:$1]
    ErrorDocument 200 "%%{ENV:challenge}.%s"
    RewriteRule ^ - [L,R=200]
</Location>

Nginix:
-----------------------------------------------------
location ~ ^/\.well-known/acme-challenge/([-_a-zA-Z0-9]+)$ {
    default_type text/plain;
    return 200 "$1.%s"
}

IIS web.config:
-----------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?><configuration>
<system.webServer><rewrite><rules><rule name="ACME-Challenge" stopProcessing="true">
 <match url="^\.well-known/acme-challenge/([-_a-zA-Z0-9]+)$" />
<action type="CustomResponse" statusCode="200" statusReason="OK" statusDescription="{R:1}.%s" />
</rule></rules></rewrite></system.webServer></configuration>


CONFIG

exit;

}

$acme->create_account( termsOfServiceAgreed => 1 );

if ($flags eq "1") {
print "Add the following DNS record to your DNS:\n";
print "_validation-persist.YOURDOMAIN.TLD 3600 IN TXT \"letsencrypt.org;accounturi=".$acme->key_id.";policy=wildcard\"\n\n";
}

if (length($ARGV[3]) > 4) {
        @ids = ();
        @csr = ();
        for ($i = 3; $i < $#ARGV + 1; $i++) {
                if (length($ARGV[$i]) > 4) {
                        push(@ids, { type => 'dns', value => $ARGV[$i] } );
                        if ($flags eq "1") {
                        push(@ids, { type => 'dns', value => "*.".$ARGV[$i] } );
                        }
                        push(@csr, $ARGV[$i]);
                }
        }
        $order = $acme->create_order( identifiers => [@ids] ) || die "Failed order creation for unknown reason. Possible blacklisted domain name or ratelimit hit.\n";
        foreach $dauth ($order->authorizations()) {
                $fdauth = $acme->get_authorization( $dauth );
                foreach $chtype ($fdauth->challenges()) {
                        if ($chtype->type() eq $valmethods[int($flags)]) {
                                $chall = Net::ACME2::Challenge->new(url => $chtype->url(), type => $chtype->type(), token => "", status => $chtype->status(), validated => $chtype->validated() );
                                $acme->accept_challenge($chall);
                        }
                }
        }

        while ($order->status() ne 'ready') {
            sleep 2;
            $acme->poll_order($order);
            if ($order->status() eq 'invalid') {
              print "Failed validation for one or more domains. Please ensure you have set up the correct records, that you have entered the correct password corresponding to your _validation-persist record, and that your CAA records are set up properly, and that you have not forgot the policy=wildcard addition to the DNS-PERSIST-01 record.\n";
              exit;
           }
        }

        $csrpem = "-----BEGIN CERTIFICATE REQUEST-----\n" . encode_base64(&genCsr($inpass, @csr)) . "-----END CERTIFICATE REQUEST-----";
        $acme->finalize_order($order,$csrpem) || die "Unable to generate certificate --> Possible failed some validation or exceeded rate limits\n";
        while ($order->status() ne 'valid') {
            sleep 1;
            $acme->poll_order($order);
        }
        $pem = $acme->get_certificate_chain($order);
        open(CERTFILE, ">".$ARGV[2]);
        print CERTFILE $pem;
        close(CERTFILE);
        print "Successfully generated LE certificate!\n";
}


sub genCsr() {
$password = $_[0];

$versionheader = "020100";
$sansobject = "";
$dn = "";
foreach $d (@_[1 .. $#_]) {
if ($flags eq "1") {
$sansobject = $sansobject . "82" . &asn1len(length($d) * 2) . unpack("H*", $d) . "82" . &asn1len((length($d) * 2) + 4) . unpack("H*", "*." . $d);
}
else
{
$sansobject = $sansobject . "82" . &asn1len(length($d) * 2) . unpack("H*", $d);
}
}
$dn = unpack("H*", $_[1]);

$sansobject = "30" . &asn1len(length($sansobject)) . $sansobject;
$sansobject = "0603551d1104" . &asn1len(length($sansobject)) . $sansobject;
$sansobject = "30" . &asn1len(length($sansobject)) . $sansobject;
$sansobject = "30" . &asn1len(length($sansobject)) . $sansobject;
$sansobject = "06092a864886f70d01090e31" . &asn1len(length($sansobject)) . $sansobject;
$sansobject = "30" . &asn1len(length($sansobject)) . $sansobject;
$sansobject = "a0" . &asn1len(length($sansobject)) . $sansobject;

$dn = "06035504030c" . &asn1len(length($dn)) . $dn;
$dn = "30" . &asn1len(length($dn)) . $dn;
$dn = "31" . &asn1len(length($dn)) . $dn;
$dn = "30" . &asn1len(length($dn)) . $dn;

$certpass = pack("H*", sha384_hex($password));
$cert = Crypt::PK::ECC->new();
$cert->import_key_raw($certpass, "secp384r1");
$spki = unpack("H*", $cert->export_key_der('public_short'));

$asn1builder = $versionheader . $dn . $spki . $sansobject;
$asn1builder = "30" . &asn1len(length($asn1builder)) . $asn1builder;
$asn1signdata = "00" . unpack("H*", $cert->sign_message(pack("H*", $asn1builder), "SHA384"));
$asn1signdata = "300a06082a8648ce3d04030303" . &asn1len(length($asn1signdata)) . $asn1signdata;
return pack("H*", "30" . &asn1len(length($asn1builder) + length($asn1signdata)) . $asn1builder . $asn1signdata);
}


sub asn1len() {
$len = $_[0];
if ($len <= 254) {
return sprintf("%02x", ($len / 2));
}
else
{
$hxlen = sprintf("%x", ($len / 2));
unless ((length($hxlen) / 2) == int(length($hxlen) / 2)) {
$hxlen = "0" . $hxlen;
}
$numlen = length($hxlen) / 2;
$firstbyte = sprintf("%02x", (128 + $numlen));
return $firstbyte . $hxlen;
}
}
