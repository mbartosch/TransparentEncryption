use Test::More tests => 25;
use strict;
use warnings;
use File::Temp;
use Data::Dumper;
use Time::HiRes qw( gettimeofday tv_interval );
use DBI;

BEGIN { use_ok('OpenXPKI::Crypto::KeyManagement::TransparentEncryption') };
require_ok('OpenXPKI::Crypto::KeyManagement::TransparentEncryption');

my $dbh = DBI->connect("dbi:SQLite:dbname=00_instantiate.sqlite", "", "");

my $sth = $dbh->prepare(
    q(
        CREATE TABLE DATAPOOL(
            NAMESPACE varchar(255),
            KEY varchar(255),
            VALUE varchar(32768)
    )));
eval {
    $sth->execute();
};

sub store_tuple {
    my $arg = shift;
    $dbh->do(q(DELETE FROM DATAPOOL WHERE (NAMESPACE=? AND KEY=?)), undef, $arg->{NAMESPACE}, $arg->{KEY});
    my $sth = $dbh->prepare(
	q(
            INSERT INTO DATAPOOL (namespace, key, value)
            VALUES (?, ?, ?)
        ));
    $sth->execute($arg->{NAMESPACE}, $arg->{KEY}, $arg->{VALUE});
}

sub retrieve_tuple {
    my $arg = shift;
    my $sth = $dbh->prepare(
	q(
            SELECT VALUE FROM DATAPOOL WHERE (NAMESPACE=? AND KEY=?)
        ));
    $sth->execute($arg->{NAMESPACE}, $arg->{KEY});
    my $row = $sth->fetch();
    if (! defined $row) {
	return;
    }
    return $row->[0];
}

# list all basenames in directory t/certs/*.pem (only numerical ones)
sub list_cert_ids {
    return map {  m{ (\d+)\.pem }xms; $_ = $1 } glob('t/certs/*.pem');
}

# get last entry in cert dir
my $last_cert_id;
sub get_last_cert_id {
    if (! defined $last_cert_id) {
	my @cert_ids = list_cert_ids();
	$last_cert_id = pop @cert_ids;
    }
    return $last_cert_id;
}

sub _encrypt_asymmetrically {
    my $arg_ref = shift;

    my $keyid = $arg_ref->{KEYID};
    my $data  = $arg_ref->{DATA};
    my $outform = $arg_ref->{OUTFORM} || 'DER';

    #print "encrypting for key id $keyid\n";
    my $tmp = File::Temp->new();
    my $filename = $tmp->filename;
    print $tmp $data;
    close $tmp;

    my $certfile = "t/certs/$keyid.pem";
    my $result;
    {
	open my $handle, "openssl smime -encrypt -outform $outform -in $tmp $certfile |" or return;
	undef $/;
	$result = <$handle>;
	close $handle;
    }
    return $result;
}


sub decrypt_asymmetrically {
    my $arg_ref = shift;

    my $keyid = $arg_ref->{KEYID};
    my $data  = $arg_ref->{DATA};

    my $tmp = File::Temp->new();
    my $filename = $tmp->filename;
    print $tmp $data;
    close $tmp;

    my $certfile = "t/certs/$keyid.pem";
    my $keyfile = "t/private/$keyid-key.pem";
    my $result;
    {
	open my $handle, "openssl smime -decrypt -inkey $keyfile -inform der -in $tmp |" or return;
	undef $/;
	$result = <$handle>;
	close $handle;
    }

    return $result;
}

sub encrypt_asymmetrically {
    my $arg_ref = shift;
    $arg_ref->{OUTFORM} = 'DER';
    return _encrypt_asymmetrically($arg_ref);
}


sub transparent_encryption_init {
    my $tenc = OpenXPKI::Crypto::KeyManagement::TransparentEncryption->new(
	{
	    KEYMANAGEMENT => 'DAY',
	}
	);

    $tenc->delegate(
	{
	    GET_CURRENT_ASYMMETRIC_KEY_ID => \&get_last_cert_id,
	    ENCRYPT_ASYMMETRICALLY        => \&encrypt_asymmetrically,
	    DECRYPT_ASYMMETRICALLY        => \&decrypt_asymmetrically,
	    STORE_TUPLE                   => \&store_tuple,
	    RETRIEVE_TUPLE                => \&retrieve_tuple,
	});
    return $tenc;
}

my $tenc = transparent_encryption_init();

my $test_data = 'abc123';

# test underlying base functions

my $current_key_id = $tenc->get_current_asymmetric_key_id();
ok($current_key_id eq '04', 'get current key id');

# asymmetric encryption
# force PEM format
my $pkcs7 = _encrypt_asymmetrically(
    {
	OUTFORM => 'PEM',
	KEYID => $current_key_id,
	DATA => $test_data,
    });
ok($pkcs7 =~ m{ \A -----BEGIN\ PKCS7----- }xms, 'generate test PEM encoded PKCS#7');

my $tmp = $tenc->encrypt_asymmetrically(
    {
	KEYID => $current_key_id,
	DATA => $test_data,
    });
ok($tmp ne '', 'encrypt asymmetrically');

my $decrypted = $tenc->decrypt_asymmetrically(
    {
	KEYID => $current_key_id,
	DATA => $tmp,
    });
ok($decrypted eq $test_data, 'decrypt asymmetrically');

# test alternate encoding
$tmp = $tenc->decode($pkcs7);

$decrypted = $tenc->decrypt_asymmetrically(
    {
	KEYID => $current_key_id,
	DATA => $tenc->decode($pkcs7),
    });
ok($decrypted eq $test_data, 'decrypt asymmetrically (plain PEM encoded PKCS7)');


# symmetric encryption
$tmp = $tenc->encrypt_symmetrically(
    {
	KEY  => pack('H*', '00' x 32),
	DATA => $test_data,
    });
#print Dumper $tmp;

# storing and retrieveing data
ok($tenc->store_tuple(
    {
	NAMESPACE => 'test',
	KEY       => 'foo',
	VALUE     => 'bar',
    }), 'store tuple data');

$tmp = $tenc->retrieve_tuple(
    {
	NAMESPACE => 'does not exist',
	KEY       => 'foo',
    });
ok(! defined $tmp, 'retrieving from non-existent namespace');

$tmp = $tenc->retrieve_tuple(
    {
	NAMESPACE => 'test',
	KEY       => 'xxx',
    });
ok(! defined $tmp, 'retrieving non-existent keys');

$tmp = $tenc->retrieve_tuple(
    {
	NAMESPACE => 'test',
	KEY       => 'foo',
    });
ok(defined $tmp, 'retrieve existing key');
ok($tmp eq 'bar', 'retrieving existing key data');

# test serialization
$tmp = $tenc->serialize_encrypted_data(
    {
	ENCRYPTION_KEY_ID => 'p7:passwordsafe1',
	DATA => 'foobar',
    });
ok($tmp eq 'p7:passwordsafe1;foobar', 'serialize tuple with encryption key id');
my $result = $tenc->deserialize_encrypted_data($tmp);

ok($result->{ENCRYPTION_KEY_ID} eq 'p7:passwordsafe1', 'deserialize encryption key id');
ok($result->{DATA} eq 'foobar', 'deserialize tuple value');


# test encoding
$tmp = $tenc->encode($test_data);
ok($tmp eq 'base64-oneline;YWJjMTIz', 'encode data');
ok($tenc->decode($tmp) eq $test_data, 'decode data');

ok($tenc->decode('xyzABC1230+/;' . $tmp) eq $test_data, 'decode data with leading cruft');

# test random data generation
$tmp = $tenc->get_random_bytes(250);
ok(length($tmp) == 250, 'get random bytes');


# now for the interesting stuff
# force asymmetric encryption of data
my $encrypted;
my $ii;
my $t0;
my $elapsed;
my $persecond;
my $count;

$count = 100;
diag("Running $count iterations...");
$t0 = [gettimeofday];
for ($ii = 0; $ii < $count; $ii++) {
    $encrypted = $tenc->encrypt($test_data, 'asymmetric');
}
$elapsed   = tv_interval($t0, [gettimeofday]);
$persecond = $count / $elapsed;
diag("Elapsed $elapsed seconds. ($persecond per second)");

ok($encrypted =~ m{ \A p7:.*;base64-oneline; }xms, 'encrypt transparently (asymmetrically)');

#diag("encrypted value: $encrypted");
diag("Running $count iterations...");
$t0 = [gettimeofday];
for ($ii = 0; $ii < $count; $ii++) {
    $tenc->decrypt($encrypted);
}
$elapsed   = tv_interval($t0, [gettimeofday]);
$persecond = $count / $elapsed;
diag("Elapsed $elapsed seconds. ($persecond per second)");

ok($tenc->decrypt($encrypted) eq $test_data, 'decrypt transparently');

# force symmetric encryption of data
$encrypted = $tenc->encrypt($test_data, 'symmetric');
ok($encrypted =~ m{ \A salted:.*;base64-oneline; }xms, 'encrypt transparently (force symmetric encryption)');
#diag("encrypted value: $encrypted");
ok($tenc->decrypt($encrypted) eq $test_data, 'decrypt transparently');

# fully transparent mode with automatic key management
$count = 1000;
$t0 = [gettimeofday];
for ($ii = 0; $ii < $count; $ii++) {
    $encrypted = $tenc->encrypt($test_data);
}
$elapsed   = tv_interval($t0, [gettimeofday]);
$persecond = $count / $elapsed;
diag("Elapsed $elapsed seconds. ($persecond per second)");

ok($encrypted =~ m{ \A salted:.*;base64-oneline; }xms, 'encrypt transparently');
#diag $encrypted;

$tenc = transparent_encryption_init();

ok($tenc->decrypt($encrypted) eq $test_data, 'decrypt transparently');
$t0 = [gettimeofday];
for ($ii = 0; $ii < $count; $ii++) {
    $tenc->decrypt($encrypted);
}
$elapsed   = tv_interval($t0, [gettimeofday]);
$persecond = $count / $elapsed;
diag("Elapsed $elapsed seconds. ($persecond per second)");

