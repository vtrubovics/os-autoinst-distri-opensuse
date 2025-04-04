# SUSE's openQA tests
#
# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Run 'kvm check' test case of EAL4 test suite
# Maintainer: QE Security <none@suse.de>
# Tags: poo#101956

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use eal4_test;

sub run {
    my ($self) = shift;

    select_console 'root-console';
    script_run('echo "# Starting kvm_check test #"');

    # Install the required packages
    zypper_call('in libvirt');

    # Upload the network xml file
    my $file = 'kvm_check_network.xml';
    assert_script_run 'wget --quiet ' . data_url("eal4/$file");
    upload_log_file("kvm_check_network.xml");

    # Check if the 'default' already exists, if yes, then undefine it
    script_run('echo "# Check if the default already exists, if yes, then undefine it"');
    script_run('echo "virsh net-list --all | grep default"');
    my $exists_default_info = script_output('virsh net-list --all | grep default', proceed_on_failure => 1);
    
    if ($exists_default_info =~ /default\s+(\S+)\s+(\S+)\s+(\S+)/) {
        script_run('echo "virsh net-destroy default"') if ($1 eq 'active');
        assert_script_run('virsh net-destroy default') if ($1 eq 'active');
        script_run('echo "virsh net-undefine default"');
        assert_script_run('virsh net-undefine default');
    }

    # Define network by parsing xml file
    script_run('echo "# Define network by parsing xml file"');
    script_run("echo 'virsh net-define $file'");
    assert_script_run("virsh net-define $file");

    # Check if the xml file is parsed successfully
    script_run('echo "# Check if the xml file is parsed successfully"');
    script_run("echo 'virsh net-list --all | grep default'");
    validate_script_output 'virsh net-list --all | grep default', qr/default\s+inactive\s+no\s+yes/;

    script_run("echo 'virsh net-start default'");
    assert_script_run('virsh net-start default');
    script_run("echo 'virsh net-list --all | grep default'");
    validate_script_output 'virsh net-list --all | grep default', qr/default\s+active\s+no\s+yes/;
    script_run('echo "# Ending kvm_check test #"');
}

sub test_flags {
    return {always_rollback => 1};
}

1;
