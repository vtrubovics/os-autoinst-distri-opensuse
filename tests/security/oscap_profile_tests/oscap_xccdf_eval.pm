# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Generic test for hardening profile in the 'scap-security-guide': detection mode
# Maintainer: QE Security
# Tags: poo#93886, poo#104943

use base 'oscap_tests';
use strict;
use warnings;
use testapi;
use utils;

sub run {
    my ($self) = @_;
    select_console 'root-console';

    $self->oscap_evaluate();
}

sub test_flags {
    return {fatal => 0};
}

1;
