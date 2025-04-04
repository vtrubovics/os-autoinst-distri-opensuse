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

    # The chrony pid file does not exist is the expected result
    if (script_run('find / -name "*chrony*" | grep \'\\.pid\'') == 0) {
        record_info('There is chronyd pid file in system', script_output('systemctl status chronyd.service'), result => 'fail');
    }

    # Check chronyd status: inactive is the expected result
    validate_script_output('systemctl status --no-pager chronyd.service', sub { m/Active: inactive/ }, proceed_on_failure => 1);
    script_run('printf "\nCheck chronyd status: inactive is the expected result\n" >> chronyd_pid_file_log.txt');
    script_run('printf "systemctl status --no-pager chronyd.service\n" >> chronyd_pid_file_log.txt');
    script_run('systemctl status --no-pager chronyd.service >> chronyd_pid_file_log.txt');

    # Start chronyd
    systemctl('start chronyd.service');

    # Check chronyd status: active is the expected result
    validate_script_output('systemctl status --no-pager chronyd.service', sub { m/Active: active/ });
    script_run('printf "\n# Check chronyd status: active is the expected result\n" >> chronyd_pid_file_log.txt');
    script_run('printf "systemctl status --no-pager chronyd.service\n" >> chronyd_pid_file_log.txt');
    script_run('systemctl status --no-pager chronyd.service >> chronyd_pid_file_log.txt');

    validate_script_output('find /run -name "*chrony*" | grep \'\\.pid\'', sub { m/chronyd\.pid/ });
    script_run('printf "find /run -name "*chrony*" | grep \'\\.pid\'\n" >> chronyd_pid_file_log.txt');
    script_run('find /run -name "*chrony*" | grep \'\\.pid\' >> chronyd_pid_file_log.txt');

    select_console 'user-console';

    # Create a temp file for testing
    assert_script_run('touch test');

    # Create file and link in /run folder, expected result: fail
    validate_script_output('ln -s test /run/testlink 2>&1', sub { m/Permission denied/ }, proceed_on_failure => 1);

    script_run('printf "\n# Create file and link in /run folder, expected result: fail\n" >> chronyd_pid_file_log.txt');
    script_run('printf "ln -s test /run/testlink\n" >> chronyd_pid_file_log.txt');
    script_run('ln -s test /run/testlink >> chronyd_pid_file_log.txt');

    # Attempt to create a file in /run, expected result: fail
    validate_script_output('touch /run/test 2>&1', sub { m/Permission denied/ }, proceed_on_failure => 1);

    script_run('printf "\n# Attempt to create a file in /run, expected result: fail\n" >> chronyd_pid_file_log.txt');
    script_run('printf "touch /run/test\n" >> chronyd_pid_file_log.txt');
    script_run('touch /run/test >> chronyd_pid_file_log.txt');
    upload_log_file("chronyd_pid_file_log.txt");
}

sub test_flags {
    return {always_rollback => 1};
}

1;
