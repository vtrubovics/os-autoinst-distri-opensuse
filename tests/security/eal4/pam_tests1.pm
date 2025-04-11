use base "consoletest";
use strict;
use warnings;
use testapi;
use utils;

# Global variables
my $test_log = '/tmp/pam_test.log';
my $expect_script = '/tmp/ssh_test.exp';
my $test_user = 'tester01';
my $test_password = 'right_test_password';
my $wrong_password = 'wrongpassword123';
my $max_attempts = 3;

sub install_expect {
    my ($self) = @_;
    return if script_run("which expect") == 0;
    
    zypper_call('in expect');
    if (script_run("which expect") != 0) {
        record_info("Expect missing", "Failed to install expect package", result => 'fail');
        return 0;
    }
    return 1;
}

sub create_expect_script {
    my ($self) = @_;
    
    # Build expect script with proper escaping
    my @expect_script = (
        '#!/usr/bin/expect -f',
        'set user [lindex $argv 0]',
        'set pass [lindex $argv 1]',
        'set max_attempts [lindex $argv 2]',
        'set attempt 1',
        '',
        'while {$attempt <= $max_attempts} {',
        '    spawn ssh -o StrictHostKeyChecking=no $user\@localhost "echo Test"',
        '    expect {',
        '        "password:" {',
        '            send "$pass\r"',
        '            expect {',
        '                "Permission denied" {',
        '                    puts "Attempt $attempt failed"',
        '                    incr attempt',
        '                }',
        '                eof',
        '            }',
        '        }',
        '        eof',
        '    }',
        '}'
    );

    # Write script with proper escaping
    my $script_content = join("\n", @expect_script);
    $script_content =~ s/'/'\\''/g;  # Escape single quotes
    assert_script_run("cat > '$expect_script' <<'EOF'\n$script_content\nEOF");
    
    # Verify script creation
    if (script_run("test -f '$expect_script'") != 0) {
        record_info("Script error", "Failed to create expect script", result => 'fail');
        return 0;
    }
    
    assert_script_run("chmod +x '$expect_script'");
    upload_logs($expect_script);  # Upload for debugging
    return 1;
}

sub test_failed_logins {
    my ($self, $user, $pass, $attempts) = @_;
    
    # Check/Create expect script
    if (script_run("test -x '$expect_script'") != 0) {
        return 0 unless $self->create_expect_script();
    }
    
    # Execute and capture output
    my $output = script_output(
        "'$expect_script' '$user' '$pass' '$attempts' 2>&1 | tee -a '$test_log'",
        proceed_on_failure => 1,
        timeout => 120
    );
    
    upload_logs($test_log);  # Upload logs after each attempt
    return $output;
}

sub run {
    my ($self) = @_;
    
    # Initialize test log
    assert_script_run("echo '=== PAM Authentication Test Started ===' > $test_log");
    assert_script_run("date >> $test_log");

    # Configuration variables
    my $test_user = 'tester01';
    my $test_password = 'right_test_password';
    my $wrong_password = 'wrongpassword123';
    my $max_attempts = 3;

    select_console('root-console');
    assert_script_run("echo '=== PAM Authentication Test Started ===' > '$test_log'");
    assert_script_run("date >> '$test_log'");
    
    # 1. Install required packages
    unless ($self->install_expect()) {

    # 1.1 Create test user and set password
    assert_script_run("useradd -m -g users $test_user");
    assert_script_run("echo '$test_user:$test_password' | chpasswd");
    script_run("printf '\nUser created: $test_user\n' >> $test_log");
    record_info("User created", "Test user $test_user created with password", result => 'ok');

    # 2. Reset login counters
    script_run("faillock --reset");
    script_run("pam_tally2 --reset 2>/dev/null || true");
    script_run("printf '\nLogin counters reset\n' >> $test_log");
    record_info("Counters reset", "Login failure counters reset", result => 'ok');

    # 3. Restart auditd
    systemctl('restart auditd');
    script_run("printf '\nAuditd restarted\n' >> $test_log");
    record_info("Auditd", "Audit daemon restarted", result => 'ok');

    # 4. Install expect if needed
    if (script_run("which expect") != 0) {
        zypper_call('in expect');
        script_run("printf '\nExpect package installed\n' >> $test_log");
        record_info("Expect", "Expect package installed", result => 'ok');
    }

    # 5. Test successful login
    my $success_output = script_output(
        "expect -c 'spawn ssh -o StrictHostKeyChecking=no $test_user\@localhost \"echo Login successful\"; " .
        "expect \"password:\"; send \"$test_password\\r\"; expect eof' 2>&1 | tee -a $test_log",
        proceed_on_failure => 1
    );

    if ($success_output =~ /Login successful/) {
        script_run("printf '\nSuccessful login output:\n$success_output\n' >> $test_log");
        record_info("Login success", "Initial login succeeded as expected", result => 'ok');
    } else {
        script_run("printf '\nFailed login output:\n$success_output\n' >> $test_log");
        record_info("Login fail", "Successful login failed", result => 'fail');
        $self->result('fail');
        return;
    }

    # 6. Test failed logins using dedicated function
    script_run("printf '\n=== Testing failed logins ===\n' >> $test_log");
    my $failed_output = $self->test_failed_logins($test_user, $wrong_password, $max_attempts);
    script_run("printf '\nFailed login attempts output:\n$failed_output\n' >> $test_log");
    record_info("Failed attempts", "Completed $max_attempts failed login attempts", result => 'ok');

    # 7. Verify account lockout
    my $faillock_status = script_output("faillock --user $test_user | tee -a $test_log");
    if ($faillock_status =~ /$test_user/) {
        script_run("printf '\nFaillock status:\n$faillock_status\n' >> $test_log");
        record_info("Lock verified", "Account locked after $max_attempts attempts", result => 'ok');
    } else {
        script_run("printf '\nFaillock status missing user:\n$faillock_status\n' >> $test_log");
        record_info("Lock fail", "Account not locked after $max_attempts attempts", result => 'fail');
        $self->result('fail');
        return;
    }

    # 8. Reset account lock
    assert_script_run("faillock --user $test_user --reset | tee -a $test_log");
    assert_script_run("pam_tally2 --user $test_user --reset 2>/dev/null || true | tee -a $test_log");
    assert_script_run("passwd -u $test_user | tee -a $test_log");
    script_run("printf '\nAccount lock reset completed\n' >> $test_log");
    record_info("Reset done", "Account lock reset completed", result => 'ok');

    # 9. Verify login works after unlock
    $success_output = script_output(
        "expect -c 'spawn ssh -o StrictHostKeyChecking=no $test_user\@localhost \"echo Login successful after unlock\"; " .
        "expect \"password:\"; send \"$test_password\\r\"; expect eof' 2>&1 | tee -a $test_log",
        proceed_on_failure => 1
    );

    if ($success_output =~ /Login successful after unlock/) {
        script_run("printf '\nPost-unlock login output:\n$success_output\n' >> $test_log");
        record_info("Unlock success", "Login succeeded after unlock", result => 'ok');
    } else {
        script_run("printf '\nPost-unlock login failed:\n$success_output\n' >> $test_log");
        record_info("Unlock fail", "Login failed after unlock", result => 'fail');
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
        "grep -r 'pam_faillock\\|pam_tally' /etc/pam.d/ | tee -a $test_log"
    );
    record_info("PAM Config", $pam_config, result => 'ok');

    # Final success message
    script_run("printf '\n=== All tests completed successfully ===\n' >> $test_log");
    record_info("Test complete", "All PAM authentication tests completed successfully", result => 'ok');
}

sub test_flags {
    return {fatal => 1};
}

sub post_fail_hook {
    my ($self) = @_;
    
    # Cleanup
    script_run("userdel -r '$test_user' 2>/dev/null || true");
    script_run("rm -f '$expect_script' '$test_log' 2>/dev/null || true");
    
    # Collect all possible logs
    $self->save_and_upload_log('journalctl -u auditd -n 50', 'auditd.log');
    $self->save_and_upload_log('faillock', 'faillock_status.log');
    upload_logs('/var/log/secure', failok => 1);
    upload_logs('/var/log/auth.log', failok => 1);
    upload_logs($test_log, failok => 1);
    upload_logs($expect_script, failok => 1);
    
    # Additional debug info
    script_run("ls -l /tmp/ >> /tmp/ls_tmp.log");
    upload_logs('/tmp/ls_tmp.log', failok => 1);
}

1;