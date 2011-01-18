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

    # keeps track of delegate methods for core functions
    my %callback_map         : ATTR;

    # emulated database (in-memory only)
    my %dummy_database       : ATTR;


    sub START {
	my ($self, $ident, $arg_ref) = @_;

	if ($encoding{$ident} !~ m{ \A (?: base64 | base64-oneline | raw) \z }xms) {
	    confess("Invalid encoding '$encoding{$ident}'");
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
	#print Dumper \%callback_map;
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
	my $enc_key_id = $arg_ref->{ENCRYPTION_KEY_ID};
	my $value      = $arg_ref->{VALUE};

	$dummy_database{$ident}->{$namespace}->{$key}->{keyid} = $enc_key_id;
	$dummy_database{$ident}->{$namespace}->{$key}->{value} = $value;
	
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
	
	my $keyid = $dummy_database{$ident}->{$namespace}->{$key}->{keyid} || '';
	my $value = $dummy_database{$ident}->{$namespace}->{$key}->{value};

	return {
	    ENCRYPTION_KEY_ID => $keyid,
	    VALUE             => $value,
	}
    }

#     sub store_key {
# 	my $self = shift;
# 	# use callback map if a callback exists
# 	if (exists $callback_map{STORE_KEY}) {
# 	    return $callback_map{STORE_KEY}(@_);
# 	}

# 	my $ident = ident $self;
# 	my $arg_ref = shift;


#     }

#     sub retrieve_key {
# 	my $self = shift;
# 	# use callback map if a callback exists
# 	if (exists $callback_map{RETRIEVE_KEY}) {
# 	    return $callback_map{RETRIEVE_KEY}(@_);
# 	}

#     }

    
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

	confess('Abstract class method');
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

	confess('Abstract class method');
	return;
    }



    sub decrypt {
	my $self = shift;
	my $ident = ident $self;
	my $arg = shift;

	my $deserialized = $self->deserialize_encrypted_data($arg);

	my $encryption_key = $deserialized->{ENCRYPTION_KEY_ID};
	my $data = $deserialized->{DATA};

	if (defined $encryption_key) {
	    if ($encryption_key =~ m{ \A p7:(.*) }xms ) {
		my $keyid = $1;

		$data = $self->decrypt_asymmetrically(
		    {
			KEYID => $keyid,
			DATA  => $self->decode($data),
		    });
	    } else {
	      croak "symmetric decryption not yet implemented";
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
	    my $encryption_key_id = $self->get_current_symmetric_key_id();
	    #$keyid = $encryption_key->{KEYID};

	    print "currenty key id: $keyid\n";

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

    #    confess('Abstract base class cannot be instantiated');
	return;
    }


    sub get_current_symmetric_key_id {
	my $self = shift;
	# use callback map if a callback exists
	if (exists $callback_map{GET_CURRENT_SYMMETRIC_KEY_ID}) {
	    return $callback_map{GET_CURRENT_SYMMETRIC_KEY_ID}(@_);
	}
	my $ident = ident $self;
	my $arg_ref = shift;

    #    confess('Abstract base class cannot be instantiated');
	return 'FIXME';
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


