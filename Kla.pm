#!/usr/bin/perl

package Kla;

use Net::LDAP;
use Authen::SASL qw(Perl);
use Authen::Krb5;
use File::Temp qw(:mktemp);
use strict;
use warnings;

our $VERSION = '0.1';

=pod

=head1 NAME

Kla - Kerberos Ldap Admin, perl libraries

=head1 SYNOPSIS

  use Kla;
  my $kla = Kla->new();
  $kla->new_user("username", password=>"s3cr1t", admin => 0);
  $kla->new_user("username_2", admin => 1);
  $kla->set_password("3xtr4_s3cr1t");
  $kla->del_user("username_3");

=head1 DESCRIPTION

Kla is an attempt at making a flexible user management system for a
network setup with both Kerberos and LDAP in the same network; for now,
Kla assumes that users have their username and numeric UID configured in
LDAP, but their password in Kerberos. It also assumes that LDAP
authentication using Kerberos will just plain work. Future versions of
Kla may remove this limitation.

Kla can be configured through a system-wide configuration file, through
a per-user configuration file, or just by modifying the configuration
values in code. See CONFIGURATION, below.

This Kla perl module is flexible, but rather crude in usage. For a
user-friendly version that is usable, have a look at the "kla" script.

=head1 CONFIGURATION

The Kla constructor will read three files. These are, in sequence:
 
 /etc/kla.cfg
 $HOME/.kla
 $HOME/.kla_cache

These are simple key-value files, in which the keys are separated from
the value by an equals sign ("="). The file may also contain comments;
comments start with a hash mark ("#") and continue until the end of the
line. The .kla_cache file is written in kla's destructor, and is used
for values that may be of use in next runs. These will all be private
variables; if you find you need to modify them to get kla to do what you
want, then please file a bug.

Upon reading each key, the constructor will store the read value in the
hash table that it will eventually bless and return as the object; the
key in the configuration file will be the key in the object's hash
table. Any internal values that Kla needs for housekeeping will be
prefixed by 'priv'; setting these manually from either configuration or
code is highly discouraged, as their behaviour, meaning, or even
existence, may change without further notice. Having said that, it is
therefore possible to modify any of the following configuration
variables from code as well as from any of the two above configuration
files, unless otherwise noted.

=head2 Configuration values

=over 3

=item binddn

The distinguished name with which to bind to the LDAP server. Example:

 binddn=uid=wouter,ou=People,dc=nixsys,dc=be

=item binddn_template

A template with which binddn will be set in case it has not been
otherwise set. This cannot be set from code, since this is checked for
only in the constructor. The template is used in an eval string.
Example:

binddn_template=uid=\" . $ENV{USER} . \",ou=People,dc=nixsys,dc=be

=item kadm_princ

The principal used for administrator privileges. If unset, then
'username/admin@REALM' is used. Example:

kadm_princ=wouter/admin@GREP.BE

=item ldapgroupbase

The LDAP search base for group entries. Example:

ldapgroupbase=ou=Groups,dc=nixsys,dc=be

=item ldapuserbase

The LDAP search base for user entries. Example:

ldapuserbase=ou=People,dc=nixsys,dc=be

=item ldapuri

The URI used to connect to the LDAP server. Example:

ldapuri=ldaps://ldap.nixsys.be

=item maxuid

The maximum correct value to be used for uidNumber attributes. Example:

maxuid=10000

=item maxgid

The maximum correct value to be used for gidNumber attributes. Example:

maxgid=10000

=item minuid

The minimum correct value to be used for uidNumber attributes. Example:

minuid=2000

=item mingid

The minimum correct value to be used for gidNumber attributes. Example:

mingid=2000

=item realm

The kerberos realm. If not set, the system-wide default realm (as
configured in /etc/krb5.conf) is used.

=item <type>ask

The definitions of a number of questions that can be asked for creating
a <type>. The value of this configuration value is a set of definitions
separated by the bar ('|') symbol; each of these definitions consists of
a set of colon-separated values. The first two of these are a variable
name and a prompt that is shown when the user needs to enter some data;
the data that is entered is then stored in a variable of the given name,
in a separate scope. The third field is optional, and can contain
options; valid options are 'd', for default value (which is then given
as a fourth field), 'o' for 'optional' (meaning that the user can leave
this field empty), and 'm' for 'multi-value'. The option 'm' implies
'o', and 'd' and 'o' are mutually exclusive; as such, it is not
necessary to enter more than one option in the same question definition.

The values that are set using these questions are used in the
'<type>vals' option, see below.

Example:

userask=firstname:Enter first name|lastname:Enter last name

=item <type>classes

A set of colon-separated strings enumerating the objectClasses that a
<type> should be assigned. Example:

userclasses=top:inetOrgPerson:organizationalPerson:shadowAccount:uidObject:posixAccount:trustAccount

=item <type>vals

A set of bar-separated templates that the system will evaluate using the
apply_string_template() sub in order to create attributes for a <type> object.
A template can contain any values set using the <type>ask configuration
value. For creating users, the system additionally sets $user
(containing the username that was used in the API call) and $uidnumber
(containing the generated UID number); for groups, the system will set
$group and $gidnumber. Example:

uservals=cn: $firstname $lastname|sn: $lastname|givenName: $firstname|uid: $user|homeDirectory:/home/$user|loginShell:/bin/bash|gecos:$firstname $lastname|userPassword: {SASL}$user\@REALM|dn: uid=$user,ou=People,dc=grep,dc=be|uidNumber: $uidnumber|gidNumber: 2000

=back

=head1 SUBROUTINES

=head2 Generic (non-OO) methods

=over 3

=item apply_string_template(TEMPLATE, VALUES)

This method will evaluate TEMPLATE (which must be a scalar) in an
environment where every element of VALUES (a hash) is available under a
scalar with the name of the key of that hash value. For example,
consider a template like this:

 dn: uid=$user, ou=People, dc=nixsys, dc=be

Then the following:

 Kla::apply_string_templates($template, { user => "wouter" });

will return:

 dn: uid=wouter, ou=People, dc=nixsys, dc=be

=cut

sub apply_string_template($\%) {
	my $retval;
	my $tmplstr = shift;
	my $vals = shift;
	my $key;
	my $val;
	my $str;
	my $pid;

	while (($key, $val) = each %$vals) {
		$str .= "my \$$key = \"$val\";";
	}
	$str .= "my \$priv_retval = \"$tmplstr\";print \$priv_retval;";
	$pid=open PIPE, "-|";
	if($pid) {
		while(<PIPE>) {
			$retval.=$_;
		}
	} else {
		eval $str;
		exit;
	}
	close PIPE;

	return $retval;
}

=pod

=back

=head2 Class methods

=over 3

=item new( )

Constructor. Accepts no arguments, will return a new Kla object. After
running the constructor, it may be necessary to run the bind( ) call.

=cut

sub new($) {
	my $class = shift;
	my $self = {};
	my $cfile;
	my $dotfile;
	my $cachefile;
	my $file;
	my $cval;

	$cfile = undef unless open($cfile, "< /etc/kla.cfg");
	$dotfile = undef unless open($dotfile, "< " . $ENV{HOME} . "/.kla");
	$cachefile = undef unless open($cachefile, "< " . $ENV{HOME} . "/.kla_cache");
	foreach $file ($cfile, $dotfile, $cachefile) {
		next unless defined($file);
		while(<$file>) {
			next if /^#/;
			s/#.*$//g;
			if(/^(.*?)=(.*)$/) {
				$self->{$1}=$2;
			}
		}
	}
	close($cfile) if defined $cfile;
	close($dotfile) if defined $dotfile;
	close($cachefile) if defined $cachefile;
	foreach $cval("minuid", "maxuid", "mingid", "maxgid") {
		if(exists($self->{"priv_$cval"}) && $self->{"priv_$cval"} eq '') {
			undef($self->{"priv_$cval"});
		}
	}
	if(!exists($self->{binddn})) {
		if(exists($self->{binddn_template})) {
			my %h = {};
			$self->{dn} = apply_string_template($self->{binddn_template}, %h);
		}
	}
	bless $self, $class;
}

sub DESTROY($) {
	my $self = shift;
	my $cachefile;
	my $i;

	if(open($cachefile, "> " . $ENV{HOME} . "/.kla_cache")) {
		for $i ("priv_minuid", "priv_mingid", "priv_maxuid", "priv_maxgid") {
			print $cachefile "$i=" . $self->{$i} . "\n" if exists($self->{$i});
		}
		close($cachefile);
	}
}

sub add_entry($$\%) {
	my $self = shift;
	my $dn = shift;
	my $vals = shift;
	my $ldap;
	my $ent;

	$ldap = $self->{priv_ldapobj};
	$ent=Net::LDAP::Entry->new($dn, %$vals);
	$ldap->add($ent);
}

=pod

=back

=head2 Object methods

=over 3

=item bind( )

This object method will bind the Kla object to the LDAP server, using
the GSSAPI SASL mechanism. Calling this method is required if changing
or searching the LDAP directory is wanted.

=cut

sub bind($) {
	my $ldap;
	my $sasl;
	my $self = shift;
	$ldap = Net::LDAP->new($self->{ldapuri}) or die $!;
	$sasl = Authen::SASL->new(mech => "GSSAPI");
	$ldap->bind($self->{binddn}, sasl => $sasl, version => 3);
	$self->{priv_ldapobj} = $ldap;
}

# Parameters:
# elemname -- prefix of the template names
# asksub -- subroutine used when input is needed. Takes one argument
#  (prompt) and returns data that has been entered by the user, or '' if
#  nothing was entered.
# errsub -- subroutine used when an input error has occurred. Takes one
#  argument (error message)
# vals -- hash table with values for ${elemname}ask values. If empty,
#  everything will be asked interactively. If some values are entered,
#  these will be skipped in the interactive prompting.
sub add_elem($$\&\&\%) {
	my $self = shift;
	my $elemname = shift;
	my $asksub = shift;
	my $errsub = shift;
	my $vals = shift;
	my $q;
	my $qstring;
	my $ent;
	my %attrs;
	my $attr;
	my @objclass = ();
	my $res;
	my $dn;

	if(!defined($self->{"${elemname}vals"}) || !defined($self->{"${elemname}ask"})) {
		die "configuration incomplete for creating ${elemname}s.";
	}
	foreach $q(split /\|/, $self->{"${elemname}ask"}) {
		my @elem = split /:/, $q;

		if(!exists($$vals{$elem[0]})) {
			my $multi=undef;
			my $optional=undef;
			my $default=undef;
			my $attrval=undef;
			my @attrvals=();
			my $ready=0;

			if(scalar(@elem) > 2) {
				my @opts = @elem[2..$#elem];
				while(defined($opts[0])) {
					my $elem = shift @opts;
					$multi=1 if $elem eq 'm';
					if(($optional && $elem eq 'd') || ($default && $elem eq 'o')) {
						die 'default and optional are mutually exclusive!';
					}
					$optional=1 if $elem eq 'o';
					$default=shift @opts if $elem eq 'd';
				}
			}
			$qstring=$elem[1];
			$qstring .= " (default=$default)" if $default;
			$qstring .= " (or empty, if not required)" if $optional;
			$qstring .= " (or empty to stop)" if $multi;
			while(!$ready) {
				$attrval = &$asksub($qstring);
				if($attrval eq '') {
					$attrval = undef;
					$attrval = $default if $default;
					$ready = 1 if $default;
					$ready = 1 if $optional;
					$ready = 1 if $multi;
				} else {
					if($multi) {
						push @attrvals, $attrval;
					} else {
						$ready=1;
					}
				}
				if (!defined($attrval) && !$ready) {
					&$errsub("That is not valid, please try again");
				}
			}
			$attrs{$elem[0]}=\@attrvals if scalar(@attrvals);
			$$vals{$elem[0]}=$attrval if scalar($attrval);
		}
	}
	$$vals{realm}=$self->{realm};
	foreach $attr(split /\|/,$self->{"${elemname}vals"}) {
		my @attr = split(/:/, $attr);
		$attrs{$attr[0]} = apply_string_template($attr[1], %$vals);
	}
	foreach (split /:/, $self->{"${elemname}classes"}) {
		push @objclass, $_;
	}
	$attrs{objectClass} = \@objclass;
	$dn = delete $attrs{dn};
	$ent = Net::LDAP::Entry->new($dn, %attrs);
	$res = $self->{priv_ldapobj}->add($ent);
	$res->code && die $res->error;
}

sub createuser($$\@\&\&\%) {
	my $self=shift;
	my $user=shift;
	my $groups=shift;
	my $asksub = shift;
	my $errsub = shift;
	my $res;
	my $ldap = $self->{priv_ldapobj};
	my $vars = shift;

	need_ldap();
	$res = $ldap->search(base => $self->{userbase},
			     filter => "(&(objectClass=posixAccount)(uid=$user))");
	$res->code && die $res->error;
	die "Could not create user: user already exists\n" if $res->count();
	$self->findHighestUid();
	$$vars{uidnumber} = $self->{priv_minuid} + 1;
	$$vars{user} = $user;
	$self->add_elem("user", $asksub, $errsub, $vars);
	my @members = ( $user );
	for my $group (@$groups) {
		$self->addmembers($group, @members);
	}
	need_krb();

}

=pod

=item creategroup(GROUPNAME, MEMBERS, VARIABLES)

Creates a new group.

The first argument should be the name of the group. If this group
already exists, creating the group will fail.

The second argument should be a reference to an array with 0 or more
elements. Every element of the array should be a username; these users
will be added to the group after it is created, by adding new memberUid
attributes.

The last argument should be a reference to a hash. This hash will be
used together with the newgroup_template configuration value and the
apply_string_template method to generate the LDIF code for the group, after
which it will be created.

If creating the group fails for some reason, then creategroup() will die
with an appropriate error message.

=cut

sub creategroup($$\@\%) {
	my $self = shift;
	my $group = shift;
	my $members = shift;
	my $vals = shift;
	my $ldap;
	my $res;
	my $member;
	my $template;

	die "Not bound yet!" unless exists($self->{priv_ldapobj});
	$ldap = $self->{priv_ldabobj};
	$res = $ldap->search(base => $self->{ldapgroupbase},
			     filter => "(&(objectClass=posixGroup)(cn=$group)",
			     scope => "sub",
			     attrs => [ 'gidNumber' ]);
	$res->code && die $res->error;
	if($res->count() > 0) {
		die "Group already exists, with gidNumber " . $res->pop_entry()->get_value("gidNumber") . "\n";
	}
	$self->findHighestGid();
	$vals->{gidnumber} = $self->{priv_mingid} + 1;
	$template = $self->{newgroup_template};
	foreach $member(@$members) {
		$template .= "\nmemberUid = $member";
	}
	$self->add_entry($template, $vals);
	$self->addmembers($group, $members);
}

=pod

=item login_admin(PASSWORD)

Log in to the Kerberos server as an admin user (username/admin@REALM).
Required for operations on the kerberos server; for password change
operations, see login().

=cut

sub login_admin($$) {
	my $self = shift;
	my $pw = shift;
	my $ctx;
	my $cc;
	my $tmpfile;

	if(!exists($self->{priv_krbctx})) {
		$self->{ctx} = Authen::Krb5::init_context();
	}
	if(!exists($self->{realm})) {
		$self->{realm} = Authen::Krb5::get_default_realm();
	}
	if(!exists($self->{kadm_princ})) {
		$self->{kadm_princ} = $ENV{USER} . "/admin\@" . $self->{realm};
	}
	if(!exists($self->{priv_kadm_cc})) {
		my $client=parse_name($self->{kadm_princ});
		my $server=parse_name("kadmin/admin\@" . $self->{realm});
		my $error;

		$tmpfile = mktemp("/tmp/krb5_adm_$<_XXXXXXX");
		$cc = Authen::Krb5::cc_resolve("FILE:$tmpfile");
		Authen::Krb5::get_in_tkt_with_password($client, $server, $pw, $cc) or die "Could not log on to Kerberos as administrator:" . error(error());
		$self->{priv_kadm_cc} = $cc;
	}
}

=pod

=item setpassword(NEWPASSWORD)

Sets the password of a user. Will use the configuration variable realm
to generate a principal based on the user. 

=cut

sub setpassword($$) {
	my $self = shift;
	my $newpw = shift;
	
	if(!defined($newpw) {
		
	}
}

sub findHighestUid($) {
	my $self = shift;
	my $ldap;
	my $res;
	my $entry;

	$ldap = $self->{priv_ldapobj};
	$self->{priv_minuid} = $self->{minuid} unless defined($self->{priv_minuid});
	do {
		$res=$ldap->search(base => $self->{userbase},
				   filter => "(objectClass=posixAccount)",
				   scope => 'sub',
				   attrs => [ 'uidNumber' ]);
		$res->code && die $res->error;
		foreach $entry ($res->entries) {
			my $val = $entry->get_value("uidNumber");
			$self->{priv_minuid} = ($val > $self->{priv_minuid} ? $val : $self->{priv_minuid});
		}
		$res=$ldap->search(base => $self->{userbase},
				   filter => "(&(objectClass=posixAccount)(uidNumber=" . ($self->{priv_minuid} + 1) . "))",
				   scope => 'sub',
				   attrs => [ 'uidNumber' ]);
	} while ($res->count());
}

sub findHighestGid($) {
	my $self = shift;
	my $ldap;
	my $res;
	my $entry;

	$ldap = $self->{priv_ldapobj};
	$self->{priv_mingid} = $self->{mingid} unless defined($self->{priv_mingid});
	do {
		$res=$ldap->search(base => $self->{ldapgroupbase},
				   filter => "(objectClass=posixGroup)",
				   scope => 'sub',
				   attrs => [ 'gidNumber' ]);
		$res->code && die->$res->error;
		foreach $entry ($res->entries) {
			my $val = $entry->get_value("gidNumber");
			$self->{priv_mingid} = ($val > $self->{priv_mingid} ? $val : $self->{priv_mingid});
		}
	} while ($res->count());
}

=pod

=back

=head1 AUTHORS

Kla was written by Wouter Verhelst <wouter@nixsys.be>. Please send bug reports
to me.

=cut
