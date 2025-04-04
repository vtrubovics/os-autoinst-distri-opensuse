# SUSE's openQA tests
#
# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Run 'chrony pid file test' test case of EAL4 test suite
# Maintainer: QE Security <none@suse.de>
# Tags: poo#111386

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use eal4_test;

sub run {
    my ($self) = shift;

    select_console 'root-console';
    script_run('echo "# Starting chrony_pid test #"');

    # The chrony pid file does not exist is the expected result
    script_run('echo "# Check chronyd status: active is the expected result #"');
    if (script_run('find / -name "*chrony*" | grep \'\\.pid\'') == 0) {
        record_info('There is chronyd pid file in system', script_output('systemctl status chronyd.service'), result => 'fail');
    }

    # Check chronyd status: inactive is the expected result
    script_run('echo "# Check chronyd status: inactive is the expected result"');
    script_run('echo "systemctl status --no-pager chronyd.service"');
    validate_script_output('systemctl status --no-pager chronyd.service', sub { m/Active: inactive/ }, proceed_on_failure => 1);

    # Start chronyd
    script_run('echo "# Start chronyd"');
    script_run('echo "start chronyd.service"');
    systemctl('start chronyd.service');

    # Check chronyd status: active is the expected result
    script_run('echo "# Check chronyd status: active is the expected result"');
    script_run('echo "systemctl status --no-pager chronyd.service"');
    validate_script_output('systemctl status --no-pager chronyd.service', sub { m/Active: active/ });

    script_run('echo "find /run -name "*chrony*" | grep \'\\.pid\'" ');
    validate_script_output('find /run -name "*chrony*" | grep \'\\.pid\'', sub { m/chronyd\.pid/ });

    select_console 'user-console';
    script_run('echo "# Selected non root user"');

    # Create a temp file for testing
    script_run('echo "# Create a temp file for testin"');
    script_run('echo "touch test"');
    assert_script_run('touch test');

    # Create file and link in /run folder, expected result: fail
    script_run('echo "# Create file and link in /run folder, expected result: fail"');
    script_run('echo "ln -s test /run/testlink 2>&1"');
    validate_script_output('ln -s test /run/testlink 2>&1', sub { m/Permission denied/ }, proceed_on_failure => 1);

    # Attempt to create a file in /run, expected result: fail
    script_run('echo "# Attempt to create a file in /run, expected result: fail"');
    script_run('echo "touch /run/test 2>&1"');
    validate_script_output('touch /run/test 2>&1', sub { m/Permission denied/ }, proceed_on_failure => 1);

    script_run('echo "# Ending chrony_pid test #"');
}

sub test_flags {
    return {always_rollback => 1};
}

1;
