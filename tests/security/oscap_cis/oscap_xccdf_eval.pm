# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Test 'cis' hardening in the 'scap-security-guide': detection mode
# Maintainer: QE Security <none@suse.de>
# Tags: poo#93886, poo#104943

use base 'oscap_tests';
use strict;
use warnings;
use testapi;
use utils;
use Utils::Architectures;

sub run {
    my ($self) = @_;
    select_console 'root-console';

    # Set expected results
    my $n_passed_rules = 0;
    my $n_failed_rules = 0;
    my @eval_match = ('');

    $self->oscap_evaluate($n_passed_rules, $n_failed_rules, \@eval_match);
}

sub test_flags {
    return {fatal => 0};
}

1;
