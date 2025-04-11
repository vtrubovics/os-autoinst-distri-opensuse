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
    return 1 if script_run("which expect") == 0;
    
    record_info("Installing", "Expect package not found, installing...");
    zypper_call('in expect');
    
    if (script_run("which expect") != 0) {
        record_info("Error", "Failed to install expect package", result => 'fail');
        return 0;
    }
    return 1;
}

sub create_expect_script {
    my ($self) = @_;
    
    # Build expect script - NO escaping of $variables
    my @script_lines = (
        '#!/usr/bin/expect -f',
        'set user [lindex $argv 0]',
        'set pass [lindex $argv 1]',
        'set max_attempts [lindex $argv 2]',
        'set attempt 1',
        '',
        'while {$attempt <= $max_attempts} {',
        '    spawn ssh -o StrictHostKeyChecking=no $user@localhost "echo Test"',
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

    # Write script using base64 to avoid escaping issues
    my $script_content = join("\n", @script_lines);
    my $encoded = encode_base64($script_content);
    assert_script_run("printf '%s' '$encoded' | base64 -d > '$expect_script'");
    
    # Verify script creation
    if (script_run("test -f '$expect_script' && grep -q '^#!/' '$expect_script'") != 0) {
        record_info("Script Error", "Failed to create valid expect script", result => 'fail');
        upload_logs($expect_script);
        return 0;
    }
    
    assert_script_run("chmod +x '$expect_script'");
    upload_logs($expect_script);
    return 1;
}

sub test_failed_logins {
    my ($self, $user, $pass, $attempts) = @_;
    
    # Check/Create expect script
    if (script_run("test -x '$expect_script'") != 0) {
        return 0 unless $self->create_expect_script();
    }
    
    # Execute with proper arguments
    my $output = script_output(
        "'$expect_script' '$user' '$pass' '$attempts' 2>&1 | tee -a '$test_log'",
        proceed_on_failure => 1,
        timeout => 120
    );
    
    return $output;
}

sub verify_account_lock {
    my ($self, $user) = @_;
    
    # Use bash log for this operation
    assert_script_run("printf '\\n=== Checking account lock status ===\\n' >> '$bash_log'");
    my $status = script_output("faillock --user '$user' | tee -a '$bash_log'");
    assert_script_run("cat '$bash_log' >> '$test_log'");
    upload_logs($bash_log);
    
    if ($status =~ /$user/m) {
        record_info("Lock Verified", "Account successfully locked after $max_attempts attempts", result => 'ok');
        return 1;
    }
    
    record_info("Lock Failed", "Account not locked as expected:\n$status", result => 'fail');
    return 0;
}

sub run {
    my ($self) = @_;
    
    # Initialize environment
    select_console('root-console');
    assert_script_run(": > '$test_log'");  # Clear main log
    assert_script_run(": > '$bash_log'");  # Clear bash log
    assert_script_run("echo '=== Test Started: ' >> '$test_log'; date >> '$test_log'");
    
    # 1. Install dependencies
    unless ($self->install_expect()) {
        $self->result('fail');
        return;
    }
    
    # 2. Create test user (log to bash_log)
    assert_script_run("printf '\\n=== Creating test user ===\\n' >> '$bash_log'");
    assert_script_run("useradd -m -g users '$test_user' >> '$bash_log' 2>&1");
    assert_script_run("echo '$test_user:$test_password' | chpasswd >> '$bash_log' 2>&1");
    assert_script_run("cat '$bash_log' >> '$test_log'");
    upload_logs($bash_log);
    record_info("User Created", "Test user setup complete", result => 'ok');
    
    # 3. Reset authentication systems
    assert_script_run("printf '\\n=== Resetting authentication ===\\n' >> '$bash_log'");
    assert_script_run("faillock --reset >> '$bash_log' 2>&1");
    assert_script_run("pam_tally2 --reset 2>/dev/null >> '$bash_log' || true");
    systemctl('restart auditd');
    assert_script_run("cat '$bash_log' >> '$test_log'");
    upload_logs($bash_log);
    
    # 4. Test successful login
    assert_script_run("printf '\\n=== Testing successful login ===\\n' >> '$bash_log'");
    my $output = script_output(
        "expect -c 'spawn ssh -o StrictHostKeyChecking=no $test_user\@localhost \"echo Login successful\"; " .
        "expect \"password:\"; send \"$test_password\\r\"; expect eof' 2>&1 | tee -a '$bash_log'",
        proceed_on_failure => 1
    );
    assert_script_run("cat '$bash_log' >> '$test_log'");
    upload_logs($bash_log);
    
    unless ($output =~ /Login successful/) {
        record_info("Login Failed", "Initial authentication failed", result => 'fail');
        $self->result('fail');
        return;
    }
    record_info("Login Success", "Initial authentication succeeded", result => 'ok');
    
    # 5. Test failed logins
    record_info("Testing", "Starting failed login attempts");
    $output = $self->test_failed_logins($test_user, $wrong_password, $max_attempts);
    
    # 6. Verify lock
    unless ($self->verify_account_lock($test_user)) {
        $self->result('fail');
        return;
    }
    
    # 7. Reset and verify unlock
    assert_script_run("printf '\\n=== Resetting account lock ===\\n' >> '$bash_log'");
    assert_script_run("faillock --user '$test_user' --reset >> '$bash_log' 2>&1");
    assert_script_run("pam_tally2 --user '$test_user' --reset 2>/dev/null >> '$bash_log' || true");
    assert_script_run("passwd -u '$test_user' >> '$bash_log' 2>&1");
    assert_script_run("cat '$bash_log' >> '$test_log'");
    upload_logs($bash_log);
    
    assert_script_run("printf '\\n=== Testing unlock ===\\n' >> '$bash_log'");
    $output = script_output(
        "expect -c 'spawn ssh -o StrictHostKeyChecking=no $test_user\@localhost \"echo Login after unlock\"; " .
        "expect \"password:\"; send \"$test_password\\r\"; expect eof' 2>&1 | tee -a '$bash_log'",
        proceed_on_failure => 1
    );
    assert_script_run("cat '$bash_log' >> '$test_log'");
    upload_logs($bash_log);
    
    unless ($output =~ /Login after unlock/) {
        record_info("Unlock Failed", "Post-unlock authentication failed", result => 'fail');
        $self->result('fail');
        return;
    }
    record_info("Unlock Success", "Account unlocked successfully", result => 'ok');
    
    # 8. Final verification
    assert_script_run("printf '\\n=== PAM Configuration ===\\n' >> '$bash_log'");
    assert_script_run("grep -r 'pam_faillock\\|pam_tally' /etc/pam.d/ >> '$bash_log' 2>&1");
    assert_script_run("cat '$bash_log' >> '$test_log'");
    upload_logs($bash_log);
    record_info("Config", "PAM configuration verified", result => 'ok');
    
    # Final cleanup
    assert_script_run("userdel -r '$test_user'");
    record_info("Complete", "All PAM tests executed successfully", result => 'ok');
}

sub test_flags {
    return {fatal => 1, milestone => 1};
}

sub post_fail_hook {
    my ($self) = @_;
    
    # Upload all log files
    upload_logs($test_log);
    upload_logs($bash_log);
    upload_logs($expect_script);
    
    # Additional debug info
    $self->save_and_upload_log('journalctl -u auditd -n 100', 'auditd.log');
    $self->save_and_upload_log('faillock', 'faillock.log');
    upload_logs('/var/log/secure', failok => 1);
    upload_logs('/var/log/auth.log', failok => 1);
    
    # System state
    script_run("ps auxf > /tmp/processes.log");
    script_run("systemctl status auditd > /tmp/auditd_status.log");
    upload_logs('/tmp/processes.log');
    upload_logs('/tmp/auditd_status.log');
    
    # Cleanup
    script_run("userdel -r '$test_user' 2>/dev/null || true");
    script_run("rm -f '$expect_script' '$test_log' '$bash_log' 2>/dev/null || true");
}

1;