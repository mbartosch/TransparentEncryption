## OpenXPKI::Crypto::KeyManagement::TransparentEncryption
##
## Written 2011 by Martin Bartosch for the OpenXPKI project
## Copyright (C) 2010, 2011 by The OpenXPKI Project
##

package OpenXPKI::Crypto::KeyManagement::TransparentEncryption;

use Class::Std;
use Carp;
use strict;
use warnings;
use English;

use MIME::Base64;
use Crypt::CBC;
use Digest::SHA1 qw( sha1_base64 );
use DateTime;

use Data::Dumper;

# use Smart::Comments;

{
    my %separation_character : ATTR( :init_arg<SEPARATION_CHARACTER>
				     :default( ';' )
				     :get<separation_character> );

    my %crypt_cbc_class      : ATTR( :init_arg<CRYPT_CBC_CLASS>
	                             :default( 'Crypt::OpenSSL::AES' )
				     :get<crypt_cbc_class> );

    my %encoding             : ATTR( :init_arg<ENCODING> 
				     :default('base64-oneline')
				     :get<encoding> );

    my %flag_encrypt_memory  : ATTR( :init_arg<MEMORYENCRYPTION>
				     :default( 1 )
				     :get<memoryencryption> );

    # possible key management policies:
    # 'INSTANCE' - one symmetric key per TransparentEncryption instance
    # 'CERT'     - one symmetric key per certificate/asymmetric key
    # 'YEAR'     - one symmetric key per year
    # 'QUARTER'  - one symmetric key per quarter
    # 'MONTH'    - one symmetric key per month
    # 'WEEK'     - one symmetric key per week
    # 'DAY'      - one symmetric key per day
    my %key_management_policy : ATTR( :init_arg<KEYMANAGEMENT>
				      :default( 'CERT' )
				      :get<key_management> );


    # storage namespace for symmetric key persistence
    my %namespace_key_storage : ATTR( :init_arg<NAMESPACE_KEY_STORAGE>
				      :default( 'sys.datapool.key.storage' )
				      :get<namespace_key_storage> );

    # storage namespace for key association
    my %namespace_key_mapping : ATTR( :init_arg<NAMESPACE_KEY_MAPPING>
				      :default( 'sys.datapool.key.mapping' )
				      :get<namespace_key_mapping> );

    # no user serviceable parts below

    # keeps track of delegate methods for core functions
    my %callback_map             : ATTR;

    # emulated database (in-memory only)
    my %dummy_database           : ATTR;

    # instance cipher instance with ephemeral key for in-memory-encryption 
    # (used to cache symmetric keys)
    my %instance_cipher_instance : ATTR;

    # unique instance id
    my %instance_id              : ATTR;

    # this variable holds 
    my %instance_memory_cache    : ATTR;


    sub START {
	my ($self, $ident, $arg_ref) = @_;

	if ($encoding{$ident} !~ m{ \A (?: base64 | base64-oneline | raw) \z }xms) {
	    confess("Invalid encoding '$encoding{$ident}'");
	}

	if ($flag_encrypt_memory{$ident} !~ m{ \A (?: 1 | 0) \z }xms) {
	    confess("Invalid in-memory encryption policy '$flag_encrypt_memory{$ident}'");
	}

	if ($key_management_policy{$ident} 
	    !~ m{ \A (?: INSTANCE | CERT 
                         | YEAR | QUARTER | MONTH | WEEK | DAY ) \z }xms) {
	    confess("Invalid key management policy '$key_management_policy{$ident}'");
	}

	$instance_memory_cache{$ident} = {};

	# the instance id is a public random string that identifies 
	# this particular class instance 
	$instance_id{$ident} = sha1_base64($self->get_random_bytes(20));

	if ($flag_encrypt_memory{$ident}) {
	    # set up instance-specific encryption key
	    
	    my $symmetric_key = $self->generate_symmetric_key();
	    # once this instance goes away it invalidates all data 
	    # encrypted with  this key
	    $instance_cipher_instance{$ident} = Crypt::CBC->new(
		-cipher     => $crypt_cbc_class{$ident},
		-key        => $symmetric_key->{KEY},
		);
	}
    }

    sub delegate {
	my $self = shift;
	my $ident = ident $self;
	my $arg_ref = shift;

	# attach delegate (i. e. callback) methods
	foreach my $method (keys %{$arg_ref}) {
	    if ($method !~ m{ \A (?: 
                STORE_TUPLE |
                RETRIEVE_TUPLE |
                ENCRYPT_ASYMMETRICALLY |
                DECRYPT_ASYMMETRICALLY |
                SERIALIZE_ENCRYPTED_DATA |
                DESERIALIZE_ENCRYPTED_DATA |
                GET_CURRENT_ASYMMETRIC_KEY_ID |
                GET_RANDOM_BYTES
                \z ) }xms) {
		confess("Invalid delegate method name '$method'");
	    }

	    if (ref $arg_ref->{$method} ne 'CODE') {
		confess("Invalid delegate method type for method '$method'");
	    }
	    $callback_map{$method} = $arg_ref->{$method};
	
	}
	if (! exists $callback_map{STORE_TUPLE} 
	    || ! exists $callback_map{RETRIEVE_TUPLE}) {
	    warn "WARNING: Running in demo mode (without persistent storage). Encrypted data will not be recoverable. Specify STORE_TUPLE and RETRIEVE_TUPLE methods in order to get rid of this warning.";
	}
	### %callback_map;
    }


    # transport-encode input data
    # unnamed arguments:
    # arg: data to encode
    # encoding: encoding to use (optional, defaults to instance default)
    sub encode {
	my $self = shift;
	my $ident = ident $self;

	my $arg = shift;
	my $encoding = shift || $encoding{$ident};

	my $blob;
	if ($encoding eq 'base64') {
	    $blob = MIME::Base64::encode_base64($arg);
	} elsif ($encoding eq 'base64-oneline') {
	    $blob = MIME::Base64::encode_base64($arg, '');
	} elsif ($encoding eq 'raw') {	 
	    $blob = $arg;
	} else {
	    confess("Invalid encoding '$encoding'");
	}
	    
	return join($separation_character{$ident},
		    $encoding,
		    $blob);
    }

    # transport-decode input data
    # unnamed arguments:
    # arg: data to decode
    sub decode {
	my $self = shift;
	my $ident = ident $self;
	my $arg = shift;
	
	my $blob;

	if ($arg =~ m{ \A -----BEGIN\ .*?----- (.*) -----END\ .*----- }xms) {
	    $blob = MIME::Base64::decode_base64($1);
	} else {
	    my $sepchar = $separation_character{$ident};

	    my ($encoding, $data) 
		= ($arg =~ m{ \A (?: [ a-z A-Z 0-9 + / ]+ $sepchar)?
                                     (base64|base64-oneline|raw)
                                     $sepchar (.*)
                              \z }xms);

	    if (! defined $encoding) {
		confess("Invalid encoding '$encoding'");
	    }	    

	    if (($encoding eq 'base64') ||
		($encoding eq 'base64-oneline')) {
		$blob = MIME::Base64::decode_base64($data);
	    } elsif ($encoding eq 'raw') {	 
		$blob = $arg;
	    }
	}

	return $blob;
    }




    # Stores the specified value in a persistent data store.
    # named arguments:
    # NAMESPACE => namespace to use
    # KEY       => string, handle for stored value, unique within NAMESPACE
    # VALUE     => value
    sub store_tuple {
	my $self = shift;
	
	# use callback map if a callback exists
	if (exists $callback_map{STORE_TUPLE}) {
	    return $callback_map{STORE_TUPLE}(@_);
	}

	my $ident = ident $self;
	my $arg_ref = shift;

	my $namespace  = $arg_ref->{NAMESPACE};
	my $key        = $arg_ref->{KEY};
	my $value      = $arg_ref->{VALUE};

	$dummy_database{$ident}->{$namespace}->{$key} = $value;

	### database: $dummy_database{$ident}
	print Dumper $dummy_database{$ident};
	return 1;
    }

    sub retrieve_tuple {
	my $self = shift;
	# use callback map if a callback exists
	if (exists $callback_map{RETRIEVE_TUPLE}) {
	    return $callback_map{RETRIEVE_TUPLE}(@_);
	}

	my $ident = ident $self;
	my $arg_ref = shift;

	my $namespace = $arg_ref->{NAMESPACE};
	my $key       = $arg_ref->{KEY};

	if (! exists $dummy_database{$ident}->{$namespace}->{$key}) {
	    return;
	}
	
	return $dummy_database{$ident}->{$namespace}->{$key};
    }

    sub serialize_encrypted_data {
	my $self = shift;
	# use callback map if a callback exists
	if (exists $callback_map{SERIALIZE_ENCRYPTED_DATA}) {
	    return $callback_map{SERIALIZE_ENCRYPTED_DATA}(@_);
	}

	my $ident = ident $self;
	my $arg_ref = shift;

	if (! exists $arg_ref->{DATA}) {
	    confess "Missing named argument DATA";
	}
	if (! exists $arg_ref->{ENCRYPTION_KEY_ID}) {
	    confess "Missing named argument ENCRYPTION_KEY_ID";
	}
	return join($separation_character{$ident},
		    $arg_ref->{ENCRYPTION_KEY_ID} || '',
		    $arg_ref->{DATA} || '',
	    );
    }

    sub deserialize_encrypted_data {
	my $self = shift;
	# use callback map if a callback exists
	if (exists $callback_map{DESERIALIZE_ENCRYPTED_DATA}) {
	    return $callback_map{DESERIALIZE_ENCRYPTED_DATA}(@_);
	}

	my $ident = ident $self;
	my $arg = shift;

	if (ref $arg ne '') {
	    ### $arg
	    confess('Invalid data type');
	}
	
	my $sepchar = $separation_character{$ident};
	my ($encryption_key_id, $data)
	    = ($arg =~ m{ \A (.*?) $sepchar (.*) \z }xms);

	if (! defined $data) {
	    confess('Could not extract data from serialized structure');
	}

	return {
	    ENCRYPTION_KEY_ID => $encryption_key_id,
	    DATA              => $data,
	};
    }
    

    # symmetrically encrypt passed string with specified key.
    # named arguments:
    # KEY => literal AES key to use for encryption
    sub encrypt_symmetrically {
	my $self = shift;
	# use callback map if a callback exists
	if (exists $callback_map{ENCRYPT_SYMMETRICALLY}) {
	    return $callback_map{ENCRYPT_SYMMETRICALLY}(@_);
	}

	my $ident = ident $self;
	my $arg_ref = shift;

	my $key = $arg_ref->{KEY};

	if (! defined $key || ($key eq '')) {
	    confess('No key specified');
	}

	my $data = $arg_ref->{DATA};
	my $cipher = Crypt::CBC->new(
	    -cipher      => $crypt_cbc_class{$ident},
	    -key         => $key,
	    );

	return $cipher->encrypt($data);
    }

    sub decrypt_symmetrically {
	my $self = shift;
	# use callback map if a callback exists
	if (exists $callback_map{DECRYPT_SYMMETRICALLY}) {
	    return $callback_map{DECRYPT_SYMMETRICALLY}(@_);
	}

	my $ident = ident $self;
	my $arg_ref = shift;

	my $key = $arg_ref->{KEY};
	### key: $key

	my $data = $arg_ref->{DATA};

 	my $cipher = Crypt::CBC->new(
 	    -cipher      => $crypt_cbc_class{$ident},
 	    -key         => $key,
 	    );

 	return $cipher->decrypt($data);
    }

    sub encrypt_asymmetrically {
	my $self = shift;
	# use callback map if a callback exists
	if (exists $callback_map{ENCRYPT_ASYMMETRICALLY}) {
	    return $callback_map{ENCRYPT_ASYMMETRICALLY}(@_);
	}
	my $ident = ident $self;
	my $arg_ref = shift;

	confess('ERROR: Cannot proceed without a means to asymmetrically encrypt data. Please implement and specify an ENCRYPT_ASYMMETRICALLY method.');
	return;
    }

    sub decrypt_asymmetrically {
	my $self = shift;
	# use callback map if a callback exists
	if (exists $callback_map{DECRYPT_ASYMMETRICALLY}) {
	    return $callback_map{DECRYPT_ASYMMETRICALLY}(@_);
	}
	my $ident = ident $self;
	my $arg_ref = shift;

	confess('ERROR: Cannot proceed without a means to asymmetrically decrypt data. Please implement and specify a DECRYPT_ASYMMETRICALLY method.');
	return;
    }



    sub decrypt {
	my $self = shift;
	my $ident = ident $self;
	my $arg = shift;

	if (ref $arg ne '') {
	    confess('Invalid data type');
	}

	my $deserialized = $self->deserialize_encrypted_data($arg);

	my $keyid = $deserialized->{ENCRYPTION_KEY_ID};
	my $data = $deserialized->{DATA};

	my ($type, $id) = ($keyid =~ m{ \A (\S+):(.*) }xms );
	if (defined $id) {
	    if ($type eq 'p7') {

		$data = $self->decrypt_asymmetrically(
		    {
			KEYID => $id,
			DATA  => $self->decode($data),
		    });
	    }
	    if ($type eq 'salted') {
		my $key = $self->retrieve_symmetric_key($id);
		### key: $key
		
		$data = $self->decrypt_symmetrically(
		    {
			KEY  => $key->{KEY},
			DATA => $self->decode($data),
		    });
	    }

	}

	return $data;
    }


    sub encrypt {
	my $self = shift;
	my $ident = ident $self;
	my $arg = shift;
	my $mode = shift || 'symmetric';

	my $value;

	my $keyid;
	if ($mode eq 'symmetric') {
	    my $encryption_key = $self->get_current_symmetric_key();
	    $keyid  = $encryption_key->{KEYID};
	    my $key = $encryption_key->{KEY};
            ### current key: $key
	    ### keyid: $keyid

	    $value = $self->serialize_encrypted_data(
		{
                    ENCRYPTION_KEY_ID => "salted:$keyid",
                    DATA => $self->encode(
			$self->encrypt_symmetrically(
			    {
				DATA  => $arg,
				KEY   => $key,
			    })),
		});
	} elsif ($mode eq 'asymmetric') {
	    $keyid = $self->get_current_asymmetric_key_id();
	    $value = $self->serialize_encrypted_data(
		{
                    ENCRYPTION_KEY_ID => "p7:$keyid",
                    DATA => $self->encode(
			$self->encrypt_asymmetrically(
			    {
				DATA  => $arg,
				KEYID => $keyid,
			    })),
		});
	} else {
	    confess("Invalid encryption mode '$mode'");
	}

	### transparently encrypted: $value
	return $value;
    }

    sub get_current_asymmetric_key_id {
	my $self = shift;
	# use callback map if a callback exists
	if (exists $callback_map{GET_CURRENT_ASYMMETRIC_KEY_ID}) {
	    return $callback_map{GET_CURRENT_ASYMMETRIC_KEY_ID}(@_);
	}
	my $ident = ident $self;
	my $arg_ref = shift;

	confess('ERROR: Cannot proceed without a means to determine the current asymmetric key id. Please implement and specify a GET_CURENT_ASYMMETRIC_KEY_ID method.');
	return;
    }


    # returns the symmetric key id to use for the next symmetric encryption
    # if none currently exists or the key management policy prohibits prolonged
    # use of the existing one create a new key
    sub get_current_symmetric_key {
	my $self = shift;

	my $ident = ident $self;
	my $arg_ref = shift;

	# policy setting (how often should we generate new symmetric keys)
	my $policy = $key_management_policy{$ident};

	my $key_handle;
	if ($policy eq 'CERT') {
	    # latest asymmetric key available
	    my $asymmetric_keyid = $self->get_current_asymmetric_key_id();

	    $key_handle = 'p7:' . $asymmetric_keyid;
	} elsif ($policy eq 'INSTANCE') {
	    $key_handle = 'i:' . $instance_id{$ident};
	} elsif ($policy eq 'YEAR') {
	    my $now = DateTime->now();
	    $key_handle = 'd:' . $now->year();
	} elsif ($policy eq 'QUARTER') {
	    my $now = DateTime->now();
	    $key_handle = 'd:' . $now->year() . 'Q' . $now->quarter();
	} elsif ($policy eq 'MONTH') {
	    my $now = DateTime->now();
	    $key_handle = 'd:' . substr($now->ymd(''), 0, 6);
	} elsif ($policy eq 'WEEK') {
	    my $now = DateTime->now();
	    $key_handle = 'd:' . $now->year() . '.' . $now->week();
	} elsif ($policy eq 'DAY') {
	    my $now = DateTime->now();
	    $key_handle = 'd:' . $now->ymd('');
	}

	my $data = $self->retrieve_tuple(
	    {
		NAMESPACE   => $namespace_key_mapping{$ident},
		KEY         => $key_handle,
	    });

	### key handle: $key_handle
	### found associated symmetric key: $data

	my $key;
	if (! defined $data) {
	    # no mapping yet for this asymmetric key, create a new key
	    
	    $key = $self->generate_symmetric_key();
	    
	    # store association in the persistent tuple
	    $self->store_tuple(
		{
		    NAMESPACE         => $namespace_key_mapping{$ident},
		    KEY               => $key_handle,
		    VALUE             => $key->{KEYID},
		});

	    my $encrypted = $self->encrypt($key->{KEY}, 'asymmetric');

	    # persist data
	    $self->store_tuple(
		{
		    NAMESPACE => $namespace_key_storage{$ident},
		    KEY       => $key->{KEYID},
		    VALUE     => $encrypted,
		});

	    # cache key in class instance
	    $self->cache_key($key);

	} else {
	    # symmetric key already exists, retrieve it
	    ### keyid: $data

	    # obtain symmetric key from persistent storage
	    $key = $self->retrieve_symmetric_key($data);
	}

	return $key;
    }

    # argument: number of random bytes to get
    sub get_random_bytes {
	my $self = shift;
	# use callback map if a callback exists
	if (exists $callback_map{GET_RANDOM_BYTES}) {
	    return $callback_map{GET_RANDOM_BYTES}(@_);
	}
	
	my $ident = ident $self;
	my $arg = shift;

        if ($arg !~ m{ \A \d+ \z }xms) {
            confess("Invalid parameter (only numbers accepted): $arg");
        }	
	my $value;
	# FIXME: also use /dev/random?
	if (-e '/dev/urandom') {
	    open my $handle, '<', '/dev/urandom';
	    read $handle, $value, $arg;
	    close $handle;
	} else {
	    open my $handle, 'openssl rand $arg |';
	    read $handle, $value, $arg;
	    close $handle;
	}

	if (defined $value && (length($value) == $arg)) {
	    return $value;
	}
	confess("Could not generate random data");
    }

    sub generate_symmetric_key : PRIVATE {
	my $self = shift;
	my $ident = ident $self;
	my $arg = shift;

	my $key = $self->get_random_bytes(32);
        ### random key: $key
	if (length($key) != 32) {
	    confess("Could not obtain random data for instance encryption key");
	}

	# convert key into hex string
	$key = unpack('H*', $key);

	my $keyid = $self->compute_key_id(
	    {
		KEY  => $key,
		LONG => 1,
	    });


	return {
	    KEY   => $key,
	    KEYID => $keyid,
	};
    }

    sub retrieve_symmetric_key : PRIVATE {
	my $self = shift;
	my $ident = ident $self;
	my $keyid = shift;

	# obtain symmetric key
	# check if it is already cached
	my $key;
	if (exists $instance_memory_cache{$ident}->{key}->{$keyid}) {
	    my $tmp = $instance_memory_cache{$ident}->{key}->{$keyid};
	    if (defined $instance_cipher_instance{$ident}) {
		$tmp = $instance_cipher_instance{$ident}->decrypt($tmp);
	    }
	    $key = {
		KEYID => $keyid,
		KEY   => $tmp,
	    };
	    return $key;
	}
	
	# get it from the encrypted store
	my $encrypted_symmetric_key = $self->retrieve_tuple(
	    {
		NAMESPACE => $namespace_key_storage{$ident},
		KEY       => $keyid,
	    });
	if (! defined $encrypted_symmetric_key) {
	    return;
	}
	
	my $symmetric_key = $self->decrypt($encrypted_symmetric_key);

	### symmetric key: $symmetric_key
	
	$key = {
	    KEYID => $self->compute_key_id(
		{
		    KEY  => $symmetric_key,
		    LONG => 1,
		}),
	    KEY   => $symmetric_key,
	};

	$self->cache_key($key);
	return $key;
    }

    sub compute_key_id : PRIVATE {
	my $self = shift;
	my $ident = ident $self;
	my $arg = shift;

	# FIXME: backwards compatibility?
	# original code:
#	my $digest = sha1_base64(join(':', 
#				      $arg->{ALGORITHM}, 
#				      $arg->{IV},
#				      $arg->{KEY}));

	my $digest = sha1_base64(join(':', 
				      $crypt_cbc_class{$ident},
				      '',
				      $arg->{KEY}));

	if ($arg->{LONG}) {
	    return $digest;
	} else {
	    return (substr($digest, 0, 8));
	}
    }

    sub cache_key : PRIVATE {
	my $self = shift;
	my $ident = ident $self;
	my $arg = shift;

	my $key = $arg->{KEY};
	if (defined $instance_cipher_instance{$ident}) {
	    $key = $instance_cipher_instance{$ident}->encrypt($key);
	}

	my $keyid = $arg->{KEYID};
	$instance_memory_cache{$ident}->{key}->{$keyid} = $key;
	return 1;
    }
}

1;
__END__

=head1 Name

OpenXPKI::Crypto::KeyManagement::TransparentEncryption

=head1 Description

This class implements a key management solution that allows to transparently
encrypt and decrypt arbitrary data. Seen from a user perspective,
encrypt() and decrypt() are the only interfaces to the class. And these
methods only require one single argument, the plaintext or ciphertext,
respectively.

Behind the scenes, TransparentEncryption automatically generates or
reinstantiates symmetric keys that are used for the actual encryption.
It also takes care of regularly creating new keys in order to avoid
excessive use of one single key which is never exchanged over time.

To make that possible, TransparentEncryption requires a persistent 
store which is used to store encrypted keys and key association metadata.

Ultimately, all symmetric keys are encrypted using asymmetric encryption.
Newly created symmetric keys are asymmetrically encrypted to the currently
used asymmetric key. In order to reinstantiate an archived symmetric key,
TransparentEncryption uses the asymmetric key to decrypt the value pulled
from the persistent store.

If a class instance has read access to the underlying key storage which
was used when the encrypted input data was originally encrypted, and
can access the asymmetric keys used for protecting the symmetric keys, it 
can decrypt any data previously encrypted.


=head2 Design goals

=over

=item * Simplicity

Limit the primary user interface to encrypt() and decrypt() which do their 
magic behind the scenes.

=item * Automatic key management

A symmetric key is used for encryption only for a certain period. 
After this period has passed, a new symmetric key is generated 
(while still allowing older encrypted data to be decrypted using the 
old keys).

Generation and retrieval of symmetric keys is handled by this 
key management class fully automatically.

=item * Speed

Encryption/decryption uses symmetric keys for high throughput. 

=item * Key caching

The class caches symmetric keys in memory throughout the lifetime of
an instance once they have been used.

=item * In memory encryption

Keys stored in memory are encrypted using a instance-specific 
ephemeral key (memory encryption can be disabled in order to gain 
performance benefits).

=item * Abstraction and versatility

The class itself is highly abstract, it allows (and requires) a user
to implement most underlying methods, most importantly the mechanisms
for encrypting a string for a public key, to decrypt an encrypted string
and to get the currently used asymmetric key id.

=item * Backwards compatibility

Encrypted data generated by older versions of the OpenXPKI Datapool 
implementation can be decrypted (this class was intended as a replacement 
for the old 'inline' implementation). 

In particular, encrypt() always
writes data in the new serialization format, whereas decrypt() can both
handle the old and the new format.

=back


=head1 Methods

=head2 new()

Constructor, returns a new class instance. Accepts the following named
parameters:

=over

=item * MEMORYENCRYPTION

Flag that determines if caches symmetric keys are stored encrypted in memory.
Allowed values: '0', '1'. Default: '1'

=item * KEYMANAGEMENT

This setting determines how often a new symmetric key is generated. 
Effectively this setting limits the time a symmetric key is used, automatically
rolling over to a new one whenever necessary.

Default: 'CERT'

Allowed values:

=over

=item * 'INSTANCE'

one symmetric key per TransparentEncryption instance

=item *  'CERT'

one symmetric key per certificate/asymmetric key

=item * 'YEAR'

one symmetric key per year

=item * 'QUARTER'

one symmetric key per quarter

=item * 'MONTH'

one symmetric key per month

=item * 'WEEK'

one symmetric key per week

=item * 'DAY'

one symmetric key per day

=back

Behind the scenes the class computes a "key period identifier" which
is a string that changes whenever the underlying time period is over.
E. g. if set to 'MONTH' the class computes a key period identifier of
the format YYYYMM which is used to reference the corresponding symmetric key.
Whenever the class tries to obtain a symmetric key for encryption, it first
looks in the database if there is already an existing one for the specified
key period identifier. If there is none, a new key is computed, encrypted
and stored in the database. In addition the corresponding mapping between
key period identifier and key id is stored in the database.

=item * NAMESPACE_KEY_STORAGE

Persistent storage namespace to use for storing encrypted symmetric keys.
Default: 'sys.datapool.key.storage'

=item * NAMESPACE_KEY_MAPPING

Persistent storage namespace to use for storing mapping information from
key period identifier to symmetric key id.
Default: 'sys.datapool.key.mapping'

=item * ENCODING

Encoding mechanism. Allowed values: 'base64', 'base64-oneline', 'raw'. 
Default: 'base64-oneline'

=item * SEPARATION_CHARACTER

Character used to separate fields in serialized output. Default: ';'

=item * CRYPT_CBC_CLASS

CBC class used for symmetric encryption. Default: 'Crypt::OpenSSL::AES'

=back


=head2 delegate()

Set delegate (callback) methods for base operations. After instantiating
the class instance with new() the caller must at least delegate the mandatory
methods via this call.

The following delegate method ids are available:

=over

=item * ENCRYPT_ASYMMETRICALLY (mandatory)

The custom function should accept two mandatory named parameters, 'KEYID' 
and 'DATA'.
DATA is the clear text to be encrypted (may be binary data). KEYID is a 
symbolic reference that uniquely identifies the asymmetric key to use. 

KEYIDs must be consistent throughout the use of this class, but 
otherwise can have arbitrary semantics.

The function should return the encrypted value (may be binary data).

On error the function should throw an exception (or die) instead of returning
an undef.

=item * DECRYPT_ASYMMETRICALLY (mandatory)

The custom function should accept two mandatory named parameters, 'KEYID' 
and 'DATA'.
DATA is the cipher text to be decrypted (may be binary data). KEYID is a 
symbolic reference that uniquely identifies the asymmetric key that was used
for encrypting the data. 

KEYIDs must be consistent throughout the use of this class, but 
otherwise can have arbitrary semantics.

The function should return the decrypted value (may be binary data).

On error the function should throw an exception (or die) instead of returning
an undef.

=item * GET_CURRENT_ASYMMETRIC_KEY_ID (mandatory)

This function should return the KEYID of the asymmetric key that 
should currently be used for new asymmetric encryption operations.

The function does not accept any input parameters.

On error the function should throw an exception (or die) instead of returning
an undef.

=item * STORE_TUPLE (strongly recommended)

This custom function should accept three named parameters, 'NAMESPACE',
'KEY' and 'VALUE'. 

Its purpose is to persistently store the content of 'VALUE' indexed by
a key formed by 'NAMESPACE' and 'KEY'. Within 'NAMESPACE' values indexed
by 'KEY' are unique. If an existing ('NAMESPACE', 'KEY') selector is
specified, the function should overwrite the existing value.

'NAMESPACE' and 'KEY' are printable strings. 'VALUE' is normally a printable
string (unless 'raw' encoding is chosen during initialization, in which
case this function may either silently process the data or die with an error).

If this function is not implemented, encrypted values can only be decrypted
by the same instance of the class. Once the class instance dies, encrypted
values are lost forever. The class prints a warning if this method is not
implemented.

On error the function should throw an exception (or die) instead of returning
an undef.

=item * RETRIEVE_TUPLE (strongly recommended)

This custom function should accept two named parameters, 'NAMESPACE' and
'KEY'.

Its purpose is to retrieve and return the stored value indexed by a 
key formed by  'NAMESPACE' and 'KEY'. 
If no value exists, it should return undef.

'NAMESPACE' and 'KEY' are printable strings.

On error the function should throw an exception (or die) instead of returning
an undef.

=item * SERIALIZE_ENCRYPTED_DATA

The custom function should accept two mandatory named parameters, 
'ENCRYPTION_KEY_ID' and 'DATA'.

It returns a string containing a serialized representation of the supplied
parameters.

On error the function should throw an exception (or die) instead of returning
an undef.

=item * DESERIALIZE_ENCRYPTED_DATA

The custom function should accept one literal parameter containing the 
serialized string to deserialize. See SERIALIZE_ENCRYPTED_DATA.

It returns a hash ref containing the deserialized values.
The keys of the hash ref returned are 'ENCRYPTION_KEY_ID' and 'DATA'.

On error the function should throw an exception (or die) instead of returning
an undef.

=item * GET_RANDOM_BYTES

The custom function should accept one literal parameter (integer). The
argument specifies the number of random bytes to generate. The function
should compute the specified amount of cryptographically secure random
data and return it as a scalar (binary data).

On error the function should throw an exception (or die) instead of returning
an undef.

=back

=head2 encrypt()

Transparently encrypts the passed data. Returns the serialized representation
of the encryption result. Input may be arbitrary binary data.

If a second argument is supplied, it influences the encryption mechanism.
Possible values for the second argument is 'symmetric' default and 
'asymmetric'. If 'asymmetric' is supplied, the method encrypts the passed
value asymmetrically. The main disadvantage is a much lower speed compared
to the 'symmetric' encryption.

Unless internal encoding is set to 'raw' the returned value will be 
a printable string.

=head2 decrypt()

Transparently decrypts the argument. Return value may be binary data.

=head2 can_decrypt()

Returns true if the class can decrypt the encrypted value passed to the
method.

=head1 Examples

    sub get_last_cert_id { 
        ...
        return $cert_id;
    }

    sub encrypt_asymmetrically() {
        my $arg_ref = shift;

        my $keyid = $arg_ref->{KEYID};
        my $data  = $arg_ref->{DATA};
        ...
	return $encrypted;
    }

    sub decrypt_asymmetrically() {
        my $arg_ref = shift;

        my $keyid = $arg_ref->{KEYID};
        my $data  = $arg_ref->{DATA};
        ...
	return $decrypted;
    }

    sub store_tuple {
        my $arg = shift;
        ...
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
        ...
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

    # have one new symmetric key each day
    my $tenc = 
        OpenXPKI::Crypto::KeyManagement::TransparentEncryption->new({
	    KEYMANAGEMENT => 'DAY',
	});

    # delegate required methods
    $tenc->delegate({
        GET_CURRENT_ASYMMETRIC_KEY_ID => \&get_last_cert_id,
	ENCRYPT_ASYMMETRICALLY        => \&encrypt_asymmetrically,
	DECRYPT_ASYMMETRICALLY        => \&decrypt_asymmetrically,
	STORE_TUPLE                   => \&store_tuple,
	RETRIEVE_TUPLE                => \&retrieve_tuple,
	});

    my $encrypted = $tenc->encrypt('foobar');
    my $decrypted = $tenc->decrypt($encrypted);


=head1 Internal methods

=head2 encode($data, $encoding)

Returns the encoding of $data using the specified encoding. If encoding
is not specified the method uses the default encoding set for the class
instance.

Allowed encodings: 'base64-oneline', 'base64', 'raw'

See "Encoded data" below.

=head2 decode()

See encode(). Reverses the encoding operation using the encoding mechanism
included in the encoded string.

In contrast to encode() this method supports decoding PEM encoded blocks.


=head2 


=head1 Data structures and formats

  <digit> ::= [ 0-9 ]

  <hexdigit> ::= <digit> | [ a-f ]

  <byte> ::= [ 0x00 - 0xff ]

  <bytes> ::= <byte> | <byte> <bytes>

  <base64-char> ::= [ A-Z a-z 0-9 + / ]

  <base64-chars> ::= <base64-char> | <base64-char> <base64-chars>

=head2 Raw data

Raw data is a literal byte string:

  <data> ::= <bytes>

=head2 Encoded data

Encoded data carries arbitrary binary data, possibly encoded in a printable
representation. When encoding data only the <encoding> types are used.

Decoding also supports <pem-data> for backward compatibility.

  <encoding> ::= "raw" | "base64" | "base64-oneline"

  <pem-data> ::= "-----BEGIN .*-----" <base64-chars> "-----END .*-----"

  <key-id> ::= <base64-chars>

  <encoded-data> ::= <encoding> ";" <data> | 
                   <key-id> ";" <encoding> ";" <data> | 
                   <pem-data>


=head2 Key identifier

The key identifier describes the encryption key used for the payload. It is
used to reference the necessary key during encryption of the data.

Three key types are supported:

=over

=item * Asymmetric encryption key (data is asymmetrically encrypted for key LABEL)

For asymmetric keys the symbolic key name is mentioned, it is the responsibility
of the asymmetric decryption function to obtain and use the corresponding
key. Asymmetric keys have the format 'p7:LABEL'

=item * Symmetric encryption key with OpenSSL compatible salting

The symmetric key specification references a key string that is used to
derive the actual key used for encryption. A symmetric key has the format
'salted:LABEL'.

=item * Old symmetric key specification

The old symmetric key specification is a simple raw hex string, identifying 
the symmetric key to be used.
Old symmetric keys contain the IV in the key specification, not in the actual
encrypted payload. The same IV is used for all encryption/decryption 
operations with this key.
The old format is only supported read-only (for compatibility reasons) 
and will not be used for encrypting new data.

=back

The formal definition for a key identifier is as follows:

  <key-type> ::= "p7" | "salted"

  <label> ::= <hex-string>

  <key-identifier> ::= <key-type> ":" <label> | <label>


=head2 Persisted keys

Symmetric keys are persisted using the tuple store. 


=head3 

Encrypted data is encoded in a transport format that identifies the symmetric
key that was used for encrypting the data. The symmetric key is identified
by the Base64 encoding of its SHA1 hash.

