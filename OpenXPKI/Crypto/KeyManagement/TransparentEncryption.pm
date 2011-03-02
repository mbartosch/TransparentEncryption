## OpenXPKI::Crypto::KeyManagement::TransparentEncryption
##
## Written 2010 by Martin Bartosch for the OpenXPKI project
## Copyright (C) 2010 by The OpenXPKI Project
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

use Data::Dumper;

# use Smart::Comments;

{
    #my %encryption_key_id : ATTR( :init_arg<ENCRYPTION_KEY_ID>
    #			      :default( '' ) 
    #			      :get<encryption_key_id> );
    my %separation_character : ATTR( :init_arg<SEPARATION_CHARACTER>
				     :default( ';' )
				     :get<separation_character> );

    my %crypt_cbc_class      : ATTR( :init_arg<CRYPT_CBC_CLASS>
	                             :default( 'Crypt::OpenSSL::AES' )
				     :get<crypt_cbc_class> );

    my %encoding             : ATTR( :init_arg<ENCODING> 
				     :default('base64-oneline') );

    my %flag_encrypt_memory  : ATTR( :init_arg<MEMORYENCRYPTION>
				     :default( 1 ) );

    # possible key management policies:
    # 'INSTANCE' - one symmetric key per TransparentEncryption instance
    # 'CERT'     - one symmetric key per asymmetric key
    # 'YEAR'     - one symmetric key per year
    # 'MONTH'    - one symmetric key per month
    # 'WEEK'     - one symmetric key per week
    # 'DAY'      - one symmetric key per day
    my %key_management_policy : ATTR( :init_arg<KEYMANAGEMENT>
				      :default( 'CERT' ) );


    # possible rekeying policies:
    # 'AUTOMATIC' - automatic rekeying
    # 'MANUAL'    - manual rekeying
    my %rekeying_policy       : ATTR( :init_arg<REKEYING>
				      :default( 'AUTOMATIC' ) );

    # storage namespace for symmetric key persistence
    my %namespace_key_storage : ATTR( :init_arg<NAMESPACE_KEY_STORAGE>
				      :default( 'sys.datapool.key.storage' ) );

    # storage namespace for key association
    my %namespace_key_mapping : ATTR( :init_arg<NAMESPACE_KEY_MAPPING>
				      :default( 'sys.datapool.key.mapping' ) );

    # no user serviceable parts below

    # keeps track of delegate methods for core functions
    my %callback_map         : ATTR;

    # emulated database (in-memory only)
    my %dummy_database       : ATTR;

    #my %random_source        : ATTR;

    # instance cipher instance with ephemeral key for in-memory-encryption 
    # (used to cache symmetric keys)
    my %instance_cipher_instance : ATTR;

    # this variable holds 
    my %instance_memory_cache : ATTR;


    sub START {
	my ($self, $ident, $arg_ref) = @_;

	if ($encoding{$ident} !~ m{ \A (?: base64 | base64-oneline | raw) \z }xms) {
	    confess("Invalid encoding '$encoding{$ident}'");
	}

	if ($flag_encrypt_memory{$ident} !~ m{ \A (?: 1 | 0) \z }xms) {
	    confess("Invalid in-memory encryption policy '$flag_encrypt_memory{$ident}'");
	}

	if ($key_management_policy{$ident} !~ m{ \A (?: INSTANCE | CERT | YEAR | MONTH | WEEK | DAY ) \z }xms) {
	    confess("Invalid key management policy '$key_management_policy{$ident}'");
	}

	if ($rekeying_policy{$ident} !~ m{ \A (?: AUTOMATIC | MANUAL ) \z }xms) {
	    confess("Invalid rekeying policy '$rekeying_policy{$ident}'");
	}



	$instance_memory_cache{$ident} = {};

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

	$dummy_database{$ident}->{$namespace}->{$key}->{value} = $value;

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
	
	my $value = $dummy_database{$ident}->{$namespace}->{$key}->{value};

	return {
	    VALUE             => $value,
	}
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

    sub rekey {
	my $self = shift;
	my $ident = ident $self;
	my $arg = shift;

	confess('Rekeying not yet implemented');
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
	# use callback map if a callback exists
	if (exists $callback_map{GET_CURRENT_SYMMETRIC_KEY_ID}) {
	    return $callback_map{GET_CURRENT_SYMMETRIC_KEY_ID}(@_);
	}
	my $ident = ident $self;
	my $arg_ref = shift;

	my $key;

	# FIXME: associate key with symmetric key and consider policy settings
	my $asymmetric_keyid = $self->get_current_asymmetric_key_id();

	my $data = $self->retrieve_tuple(
	    {
		NAMESPACE   => $namespace_key_mapping{$ident},
		KEY         => 'p7:' . $asymmetric_keyid,
	    });

	### asymmetric key id: $asymmetric_keyid
	### found associated symmetric key: $data

	if (! defined $data) {
	    # no mapping yet for this asymmetric key, create a new key
	    
	    $key = $self->generate_symmetric_key();
	    
	    # store association in the persistent tuple
	    $self->store_tuple(
		{
		    NAMESPACE         => $namespace_key_mapping{$ident},
		    KEY               => 'p7:' . $asymmetric_keyid,
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
	    my $keyid = $data->{VALUE};
	    ### keyid: $keyid

	    # obtain symmetric key from persistent storage
	    $key = $self->retrieve_symmetric_key($keyid);
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
	# FIXME: also use /dev/random
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
	
	my $symmetric_key = $self->decrypt(
	    $encrypted_symmetric_key->{VALUE}
	    );

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
#	print Dumper $instance_memory_cache{$ident};
	return 1;
    }
}

1;
__END__

=head1 Name

OpenXPKI::Crypto::KeyManagement::TransparentEncryption

=head1 Description

This class implements a key management solution

=head2 Features

=head3 Rekeying

=head4 Manual rekeying

=head4 Automatic rekeying



=head1 Methods

=head2 new()

=head2 delegate()

Set delegate (callback) methods for base operations.

=head2 encrypt()

Transparently encrypts the passed data.

=head2 decrypt()

Transparently decrypts the argument.

=head2 rekey()

Perform a rekeying procedure on the stored data.

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

  <key-id-short> ::= <base64-chars>

  <encoded-data> ::= <encoding> ";" <data> | 
                   <key-id-short> ";" <encoding> ";" <data> | 
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

Symmetric keys are persisted using the tuple store. In order to get a printable
representation the key material is formatted as follows:


=head3 


