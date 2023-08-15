# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Test 'pci-dss' hardening in the 'scap-security-guide': detection mode
# Maintainer: QE Security <none@suse.de>
# Tags: poo#93886, poo#104943

use base 'oscap_tests';
use strict;
use warnings;
use testapi;
use utils;
use Utils::Architectures;
use version_utils qw(is_sle);

sub run {
    my ($self) = @_;
    select_console 'root-console';

    # Get ds file and profile ID
    my $f_ssg_ds = is_sle ? $oscap_tests::f_ssg_sle_ds : $oscap_tests::f_ssg_tw_ds;
    my $profile_ID = is_sle ? $oscap_tests::profile_ID_sle_pci_dss : $oscap_tests::profile_ID_tw;
    # my $bash_script = is_sle ? $oscap_tests::sle_version . $oscap_tests::bash_script_pci_dss : $oscap_tests::bash_script_standart;
    # my $b_miss_rem_pattern = $oscap_tests::bash_miss_rem_pattern;
    # my $b_rem_pattern = $oscap_tests::bash_rem_pattern;

    my $n_passed_rules = 120;
    my $n_failed_rules = 0;

    if (is_s390x) {
        $n_passed_rules = 120;
        $n_failed_rules = 0;
    }
    my @eval_match = ('');
      
    # my $expected_to_fail_rules;
    # my $expected_to_fail_rules_count;
    # my $expected_to_pass_rules;
    # my $expected_to_pass_rules_count;

    # $self->get_bash_expected_results ($b_miss_rem_pattern, $b_rem_pattern, $bash_script, $expected_to_fail_rules, $expected_to_fail_rules_count, $expected_to_pass_rules, $expected_to_pass_rules_count);
    
    # @eval_match = @$expected_to_fail_rules;
    
    # $self->oscap_evaluate($f_ssg_ds, $profile_ID, $expected_to_pass_rules_count, $expected_to_fail_rules_count, \@eval_match);
    $self->oscap_evaluate($f_ssg_ds, $profile_ID, $n_passed_rules, $n_failed_rules, \@eval_match);
}

sub test_flags {
    return {always_rollback => 1};
}

1;
