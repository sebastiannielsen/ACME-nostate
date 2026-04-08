#!/usr/bin/perl


use Net::ACME2;
use Net::ACME2::LetsEncrypt;
use Digest::SHA qw(sha384_hex);
use MIME::Base64;
use Crypt::Perl::ECDSA;
use Crypt::Perl::ECDSA::Parse;
use Crypt::Perl::PKCS10;
use Crypt::PK::ECC;

$inpass = $ARGV[0];

if (length($inpass) < 1) {
print "Password cannot be blank. Use a secure password to prevent someone guessing your private key.\n";
exit;
}

$acctpassword = pack("H*", sha384_hex($inpass."-"));

$acct = Crypt::PK::ECC->new();
$acct->import_key_raw($acctpassword, "secp384r1");

$certpass = pack("H*", sha384_hex($inpass));

$cert = Crypt::PK::ECC->new();
$cert->import_key_raw($certpass, "secp384r1");
$crtkey = Crypt::Perl::ECDSA::Parse::private($cert->export_key_pem('private'));

if ($ARGV[2] eq "export") {
open(PEMFILE, ">".$ARGV[1]);
print PEMFILE $cert->export_key_pem('private');
close(PEMFILE);
print "Written private key to ".$ARGV[1]."\n";
exit;
}

$acme = Net::ACME2::LetsEncrypt->new( key => $acct->export_key_pem('private'), environment => 'staging');
$acme->create_account( termsOfServiceAgreed => 1 );

print "Add the following DNS record to your DNS:\n";
print "_validation-persist.YOURDOMAIN.TLD 3600 IN TXT \"letsencrypt.org;accounturi=".$acme->key_id.";policy=wildcard\"\n\n";

if (length($ARGV[2]) > 4) {
        @ids = ();
        @csr = ();
        for ($i = 2; $i < $#ARGV + 1; $i++) {
                if (length($ARGV[$i]) > 4) {
                        push(@ids, { type => 'dns', value => $ARGV[$i] } );
                        push(@ids, { type => 'dns', value => "*.".$ARGV[$i] } );
                        push(@csr, [ dNSName => $ARGV[$i] ]);
                        push(@csr, [ dNSName => "*.".$ARGV[$i] ]);
                }
        }
        $order = $acme->create_order( identifiers => [@ids] ) || die "Failed order creation for unknown reason. Possible blacklisted domain name or ratelimit hit.\n";
        foreach $dauth ($order->authorizations()) {
                $fdauth = $acme->get_authorization( $dauth );
                foreach $chtype ($fdauth->challenges()) {
                        if ($chtype->type() eq "dns-persist-01") {
                                $chall = Net::ACME2::Challenge->new(url => $chtype->url(), type => $chtype->type(), token => "", status => $chtype->status(), validated =>>
                                $acme->accept_challenge($chall);
                        }
                }
        }

        while ($order->status() ne 'ready') {
            sleep 2;
            $acme->poll_order($order);
            if ($order->status() eq 'invalid') {
              print "Failed validation for one or more domains. Please ensure you have set up the correct records, that you have entered the correct password correspondin>
              exit;
           }
        }


        $pkcs10 = Crypt::Perl::PKCS10->new(key => $crtkey, (subject => [commonName => ''],attributes => [[ 'extensionRequest',[ 'subjectAltName', @csr],],]));
        $acme->finalize_order($order,$pkcs10->to_pem()) || die "Unable to generate certificate --> Possible failed some validation or exceeded rate limits\n";
        while ($order->status() ne 'valid') {
            sleep 1;
            $acme->poll_order($order);
        }
        $pem = $acme->get_certificate_chain($order);
        open(CERTFILE, ">".$ARGV[1]);
        print CERTFILE $pem;
        close(CERTFILE);
        print "Successfully generated LE certificate!\n";
}

