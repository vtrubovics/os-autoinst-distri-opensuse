# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Test 'stig' hardening in the 'scap-security-guide': ansible mitigation mode
# Maintainer: QE Security <none@suse.de>
# Tags:

use base 'oscap_tests';
use strict;
use warnings;
use testapi;
use utils;
use version_utils qw(is_sle);

sub run {
    my ($self) = @_; 
    my $is_ansible = 1;
    
    # Get ds file and profile ID, etc.
    my $f_ssg_ds = is_sle ? $oscap_tests::f_ssg_sle_ds : $oscap_tests::f_ssg_tw_ds;
    my $version = "sle" . get_required_var('VERSION') =~ s/([0-9]+).*/$1/r;
    my $profile_ID = is_sle ? $version . $oscap_tests::ansible_playbook_sle_stig : $oscap_tests::ansible_playbook_standart;
    
    $oscap_tests::ansible_remediation = 1;
    $self->oscap_remediate($f_ssg_ds, $profile_ID);
}

sub test_flags {
    # Do not rollback as next test module will be run on this test environments
    return {milestone => 1, always_rollback => 0};

}

1;
