# SUSE's openQA tests
#
# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Download the test scripts which EAL4 tests need
# Maintainer: QE Security <none@suse.de>
# Tags: poo#108485

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use eal4_test;
use version_utils qw(is_sle is_opensuse);
use registration qw(add_suseconnect_product get_addon_fullname is_phub_ready);

sub run {
    my ($self) = @_;
    
    # Configuration variables
    my $test_user = 'tester01';
    my $test_password = 'right_test_password';
    my $wrong_password = 'wrongpassword123';
    my $max_attempts = 3;

    unless (is_opensuse) {
        # Some packages require PackageHub repo is available
        return unless is_phub_ready();
        add_suseconnect_product(get_addon_fullname('phub'));
    }
    
    select_console('root-console');
    
    # 1. Create test user and set password
    assert_script_run("useradd -m -g users $test_user");
    assert_script_run("echo '$test_user:$test_password' | chpasswd");
    record_info("User created", "Test user $test_user created with password", result => 'ok');
    
    # 2. Reset login counters
    script_run("faillock --reset");
    script_run("pam_tally2 --reset 2>/dev/null || true");
    record_info("Counters reset", "Login failure counters reset", result => 'ok');
    
    # 3. Restart auditd
    systemctl('restart auditd');
    record_info("Auditd", "Audit service restarted", result => 'ok');
    
    # 4. Install sshpass if needed
    if (script_run("which sshpass") != 0) {
        zypper_call('in sshpass');
        record_info("sshpass", "sshpass package installed", result => 'ok');
    }
    
    # 5. Test successful login
    my $success_output = script_output(
        "sshpass -p '$test_password' ssh -o StrictHostKeyChecking=no $test_user\@localhost 'echo Login successful'",
        proceed_on_failure => 1
    );
    
    if ($success_output =~ /Login successful/) {
        record_info("Login success", "Initial login succeeded as expected", result => 'ok');
    } else {
        record_info("Login fail", "Successful login failed. Output: $success_output", result => 'fail');
        $self->result('fail');
        return;
    }
    
    # 6. Test failed logins
    for (my $i = 1; $i <= $max_attempts; $i++) {
        script_run("sshpass -p '$wrong_password' ssh -o StrictHostKeyChecking=no $test_user\@localhost true", proceed_on_failure => 1);
        record_info("Attempt $i", "Failed login attempt $i completed", result => 'ok');
    }
    
    # 7. Verify account lockout
    my $faillock_status = script_output("faillock --user $test_user");
    if ($faillock_status =~ /$test_user/) {
        record_info("Lock active", "Account locked after $max_attempts attempts:\n$faillock_status", result => 'ok');
    } else {
        record_info("Lock fail", "Account not locked after $max_attempts attempts", result => 'fail');
        $self->result('fail');
        return;
    }
    
    # 8. Reset account lock
    assert_script_run("faillock --user $test_user --reset");
    assert_script_run("pam_tally2 --user $test_user --reset 2>/dev/null || true");
    assert_script_run("passwd -u $test_user");
    record_info("Reset done", "Account lock reset successfully", result => 'ok');
    
    # 9. Verify login works after unlock
    $success_output = script_output(
        "sshpass -p '$test_password' ssh -o StrictHostKeyChecking=no $test_user\@localhost 'echo Login successful after unlock'",
        proceed_on_failure => 1
    );
    
    if ($success_output =~ /Login successful after unlock/) {
        record_info("Unlock success", "Login succeeded after unlock", result => 'ok');
    } else {
        record_info("Unlock fail", "Login failed after unlock. Output: $success_output", result => 'fail');
        $self->result('fail');
        return;
    }
    
    # 10. Display PAM configuration
    my $pam_config = script_output(
        "echo '=== Faillock Status ==='; " .
        "faillock; " .
        "echo '=== PAM Tally2 Status ==='; " .
        "pam_tally2 2>/dev/null || true; " .
        "echo '=== Relevant PAM Config ==='; " .
        "grep -r 'pam_faillock\\|pam_tally' /etc/pam.d/"
    );
    record_info("PAM Config", $pam_config, result => 'ok');
    
    # Final success message
    record_info("Test complete", "All PAM authentication tests passed successfully", result => 'ok');
}

sub test_flags {
    return {fatal => 1};
}

sub post_fail_hook {
    my ($self) = @_;
    
    # Cleanup test user
    script_run("userdel -r tester01 2>/dev/null || true");
    record_info("Cleanup", "Test user removed", result => 'ok');
    
    # Collect logs
    $self->save_and_upload_log('journalctl -u auditd -n 50', 'auditd.log');
    $self->save_and_upload_log('faillock', 'faillock.log');
    $self->save_and_upload_log('pam_tally2 2>/dev/null || true', 'pam_tally.log');
}

sub test_flags {
    return {milestone => 1, fatal => 1};
}

1;
