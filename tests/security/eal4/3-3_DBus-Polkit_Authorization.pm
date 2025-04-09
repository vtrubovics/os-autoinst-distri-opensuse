# SUSE's openQA tests
#
# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Run '3-3_DBus-Polkit_Authorization' test case of EAL4 test suite
# Maintainer: QE Security <none@suse.de>
# Tags: poo#180638

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use eal4_test;
use Data::Dumper;

sub run {
    my ($self) = shift;

    select_console 'root-console';

    # Calculate test time (current time + 1 hour)
    my $test_time = time() + 3600;

    # Start DBus monitoring in background
    assert_script_run("dbus-monitor --system 'interface=org.freedesktop.PolicyKit1.Authority' > /tmp/dbus-monitor.log &");
    my $monitor_pid = script_output("echo $!");

    # # Create test user (if needed - OpenQA usually has a dedicated test user)
    # assert_script_run('useradd -m -g users test_user') unless script_run('id test_user') == 0;

    # Attempt to set time as unprivileged user (should fail)
    select_console('user-console');
    my $unpriv_output = script_output(
        qq{dbus-send --system --print-reply --dest="org.freedesktop.timedate1" } .
        qq{/org/freedesktop/timedate1 org.freedesktop.timedate1.SetTime } .
        qq{int64:$test_time boolean:true boolean:true},
        proceed_on_failure => 1
    );

    # Verify unprivileged attempt was denied
    die "Polkit did not deny unprivileged access" 
        unless $unpriv_output =~ /org\.freedesktop\.DBus\.Error\.InteractiveAuthorizationRequired/;

    # Attempt to set time as root (should succeed)
    select_console('root-console');
    my $root_output = script_output(
        qq{dbus-send --system --print-reply --dest="org.freedesktop.timedate1" } .
        qq{/org/freedesktop/timedate1 org.freedesktop.timedate1.SetTime } .
        qq{int64:$test_time boolean:true boolean:true}
    );

    # Verify root attempt succeeded
    die "Root access to SetTime failed" 
        unless $root_output =~ /method return/;

    # Stop DBus monitoring and check logs
    assert_script_run("kill $monitor_pid");
    my $dbus_log = script_output("cat /tmp/dbus-monitor.log");

    # Verify Polkit authorization checks were visible
    die "Polkit authorization checks not visible" 
        unless $dbus_log =~ /org\.freedesktop\.PolicyKit1\.Authority/ &&
               $dbus_log =~ /org\.freedesktop\.timedate1\.set-time/;

    # upload_log_file("/tmp/dbus-monitor.log");
    upload_logs("/tmp/dbus-monitor.log", timeout => 600);

    # Cleanup
    # assert_script_run('userdel -r test_user');
    assert_script_run('rm -f /tmp/dbus-monitor.log');
}

sub test_flags {
    return {always_rollback => 1};
}

sub post_fail_hook {
    my ($self) = @_;
    upload_logs("$log_file");
    $self->SUPER::post_fail_hook;
}

1;
