#!/usr/bin/perl

use ExtUtils::MakeMaker;

WriteMakefile(
	NAME		=>	'Kla',
	VERSION_FROM	=>	'Kla.pm',
	depend		=>	{ Makefile => '$(VERSION_FROM)'},
);
