# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Test 'anssi_bp28_intermediary' hardening in the 'scap-security-guide' works: setup environment
# Maintainer: QE Security <none@suse.de>
# Tags: poo#93886, poo#104943

use base 'oscap_tests';
use strict;
use warnings;
use testapi;
use utils;

sub run {
    my ($self) = @_;
    $oscap_tests::ansible_remediation = 1;

    select_console 'root-console';

    $self->oscap_security_guide_setup();
}

sub test_flags {
    return {milestone => 1, fatal => 1};
}

1;