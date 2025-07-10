# Copyright 2018 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Determine type and print information about a openscap source file
# Maintainer: QE Security <none@suse.de>
# Tags: poo#36901, tc#1621169

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use openscaptest;

sub run {

    my $oscap_info = script_output "oscap info oval.xml";
    my @oval_regex_list = (
        qr/Document type: OVAL Definitions/s,
        qr/OVAL version: [0-9]+/s,
        qr/Generated: [0-9]+/s,
        qr/Imported: [0-9]+/s
    );
    validate_file_content_regex ($oscap_info, \@oval_regex_list, "oscap info oval.xml");

    my $info_xccdf = script_output "oscap info xccdf.xml";
    my @xccdf_regex_list = (
        qr/Document type: XCCDF Checklist/s,
        qr/Checklist version: [0-9]+/s,
        qr/Imported: [0-9]+/s,
        qr/Status: draft/s,
        qr/Generated: [0-9]+/s,
        qr/Resolved: false/s,
        qr/Profiles:/s,
        qr/standard/s,
        qr/Referenced check files:/s,
        qr/oval\.xml/s,
        qr/system:/s
    );
    validate_file_content_regex ($info_xccdf, \@xccdf_regex_list, "oscap info xccdf.xml");

}

1;
