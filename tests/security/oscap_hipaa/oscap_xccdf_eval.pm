# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Test 'hipaa' hardening in the 'scap-security-guide': detection mode
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
    my $profile_ID = is_sle ? $oscap_tests::profile_ID_sle_hipaa : $oscap_tests::profile_ID_tw;
    my $n_passed_rules = 97;
    my $n_failed_rules = 5;

    if (is_s390x) {
        $n_passed_rules = 97;
        $n_failed_rules = 5;
    }
my $eval_match = 'content_rule_rpm_verify_permissions,content_rule_install_hids,content_rule_accounts_passwords_pam_faillock_deny,content_rule_accounts_passwords_pam_faillock_unlock_time,content_rule_accounts_password_pam_lcredit';

    $self->oscap_evaluate($f_ssg_ds, $profile_ID, $n_passed_rules, $n_failed_rules, $eval_match);
}

sub test_flags {
    return {always_rollback => 1};
}

1;
