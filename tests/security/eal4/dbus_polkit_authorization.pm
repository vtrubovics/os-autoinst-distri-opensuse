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
    my $monitor_pid = background_script_run("dbus-monitor --system 'interface=org.freedesktop.PolicyKit1.Authority' > /tmp/dbus-monitor.log");

    # Attempt to set time as unprivileged user (should fail)
    select_console('user-console');
    my $unpriv_output = script_output(
        qq{dbus-send --system --print-reply --dest="org.freedesktop.timedate1" } .
        qq{/org/freedesktop/timedate1 org.freedesktop.timedate1.SetTime } .
        qq{int64:$test_time boolean:true boolean:true 2>&1},
        proceed_on_failure => 1,
        timeout => 30
    );

    # Verify output
    if ($unpriv_output =~ /org\.freedesktop\.DBus\.Error\.InteractiveAuthorizationRequired/) {
        record_info("Success", "Polkit correctly denied access", result => 'ok');
    } else {
        $self->result('fail');
        record_info("Failure", "Unexpected output: $unpriv_output", result => 'fail');
        save_screenshot;
        return;
    }

   # Attempt to set time as root (should succeed)
    select_console('root-console');
    my $root_output = script_output(
        qq{dbus-send --system --print-reply --dest="org.freedesktop.timedate1" } .
        qq{/org/freedesktop/timedate1 org.freedesktop.timedate1.SetTime } .
        qq{int64:$test_time boolean:true boolean:true 2>&1}
    );

    # Verify root attempt succeeded
    if ($root_output !~ /method return/) {
        record_info("Root access failure",
        "Expected successful time setting, got:\n$root_output",
        result => 'fail'
        );
        $self->result('fail');
    }
    else {
        record_info(
            "Root access pass",
            "Got uccessful time setting",
        );
    }

    # Stop DBus monitoring and check logs
    script_run("kill $monitor_pid");
    my $dbus_log = script_output("cat /tmp/dbus-monitor.log");

    # Verify Polkit authorization checks were visible
    if ($dbus_log !~ /org\.freedesktop\.PolicyKit1\.Authority/ || 
        $dbus_log !~ /org\.freedesktop\.timedate1\.set-time/) {
        record_info(
            "DBus monitor failure",
            "Missing Polkit traces in monitor log:\n$dbus_log",
            result => 'fail'
        );
        $self->result('fail');
    }
    else {
        record_info(
            "DBus monitor pass",
            "Found Polkit traces in monitor log",
        );
    }
    # upload_log_file("/tmp/dbus-monitor.log");
    upload_logs("/tmp/dbus-monitor.log", timeout => 600);

    # Cleanup
    assert_script_run('rm -f /tmp/dbus-monitor.log');
}

sub test_flags {
    return {always_rollback => 1};
}

# sub post_fail_hook {
    # my ($self) = @_;
    # upload_logs("$log_file");
    # $self->SUPER::post_fail_hook;
# }

1;
