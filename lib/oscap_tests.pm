# SUSE's openQA tests
#
# Copyright 2022 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Base module for STIG test cases
# Maintainer: QE Security <none@suse.de>

package oscap_tests;

use strict;
use warnings;
use testapi;
use utils;
use base 'opensusebasetest';
use version_utils qw(is_sle is_opensuse);
use bootloader_setup qw(add_grub_cmdline_settings);
use power_action_utils 'power_action';
use Utils::Backends 'is_pvm';
use registration qw(add_suseconnect_product get_addon_fullname is_phub_ready);

our @EXPORT = qw(
  $profile_ID
  $f_ssg_sle_ds
  $f_stdout
  $f_stderr
  $f_report
  $remediated
  $ansible_remediation
  set_ds_file
  upload_logs_reports
  pattern_count_in_file
  rules_count_in_file
  oscap_security_guide_setup
  oscap_remediate
  oscap_evaluate
  oscap_evaluate_remote
);

# The file names of scap logs and reports
our $f_stdout = 'stdout';
our $f_stderr = 'stderr';
our $f_vlevel = 'ERROR';
our $f_report = 'report.html';
our $f_pregex = '\\bpass\\b';
our $f_fregex = '\\bfail\\b';

# Set default value for 'scap-security-guide' ds file
our $f_ssg_sle_ds = '/usr/share/xml/scap/ssg/content/ssg-sle12-ds.xml';
our $f_ssg_tw_ds = '/usr/share/xml/scap/ssg/content/ssg-opensuse-ds.xml';

# Profile IDs
# Priority High:
our $profile_ID_sle_stig = 'xccdf_org.ssgproject.content_profile_stig';
our $profile_ID_sle_cis = 'xccdf_org.ssgproject.content_profile_cis';
our $profile_ID_sle_pci_dss = 'xccdf_org.ssgproject.content_profile_pci-dss';
our $profile_ID_sle_hipaa = 'xccdf_org.ssgproject.content_profile_hipaa';
our $profile_ID_sle_anssi_bp28_high = 'xccdf_org.ssgproject.content_profile_anssi_bp28_high';
# Priority Medium:
our $profile_ID_sle_anssi_bp28_enhanced = 'xccdf_org.ssgproject.content_profile_anssi_bp28_enhanced';
our $profile_ID_sle_cis_server_l1 = 'xccdf_org.ssgproject.content_profile_cis_server_l1';
our $profile_ID_sle_cis_workstation_l2 = 'xccdf_org.ssgproject.content_profile_cis_workstation_l2';
# Priority Low:
our $profile_ID_sle_anssi_bp28_intermediary = 'xccdf_org.ssgproject.content_profile_anssi_bp28_intermediary';
our $profile_ID_sle_anssi_bp28_minimal = 'xccdf_org.ssgproject.content_profile_anssi_bp28_minimal';
our $profile_ID_sle_cis_workstation_l1 = 'xccdf_org.ssgproject.content_profile_cis_workstation_l1';
our $profile_ID_tw = 'xccdf_org.ssgproject.content_profile_standard';

# Ansible playbooks
our $ansible_playbook_sle_stig = "-playbook-stig.yml";
our $ansible_playbook_sle_cis = "-playbook-cis.yml";
our $ansible_playbook_sle_pci_dss = "-playbook-pci-dss.yml";
# Only sle-15
our $ansible_playbook_sle_hipaa = "-playbook-hipaa.yml";

our $ansible_playbook_sle_anssi_bp28_high = "-playbook-anssi_bp28_high.yml";
# Priority Medium:
our $ansible_playbook_sle_anssi_bp28_enhanced = "-playbook-anssi_bp28_enhanced.yml";
our $ansible_playbook_sle_cis_server_l1 = "-playbook-cis_server_l1.yml";
our $ansible_playbook_sle_cis_workstation_l2 = "-playbook-cis_workstation_l2.yml";
# Priority Low:
our $ansible_playbook_sle_anssi_bp28_intermediary = "-playbook-anssi_bp28_intermediary.yml";
our $ansible_playbook_sle_anssi_bp28_minimal = "-playbook-anssi_bp28_minimal.yml";
our $ansible_playbook_sle_cis_workstation_l1 = "-playbook-cis_workstation_l1.yml";
our $ansible_playbook_standart = "opensuse-playbook-standard.yml";

# The OS status of remediation: '0', not remediated; '1', remediated
our $remediated = 0;

# Is it ansible remediation: '0', bash remediation; '1' ansible remediation
our $ansible_remediation = 0;

# Upload HTML report by default
set_var('UPLOAD_REPORT_HTML', 1);

# Set value for 'scap-security-guide' ds file
sub set_ds_file {

    # Set the ds file for separate product, e.g.,
    # for SLE15 the ds file is "ssg-sle15-ds.xml";
    # for SLE12 the ds file is "ssg-sle12-ds.xml"; 
    # for Tumbleweed the ds file is "ssg-opensuse-ds.xml"
    my $version = get_required_var('VERSION') =~ s/([0-9]+).*/$1/r;
    $f_ssg_sle_ds =
      '/usr/share/xml/scap/ssg/content/ssg-sle' . "$version" . '-ds.xml';
}

sub upload_logs_reports {

    # Upload logs & ouputs for reference
    my $files;
    if (is_sle) {
        $files = script_output('ls | grep "^ssg-sle.*.xml"');
    }
    else {
        $files = script_output('ls | grep "^ssg-opensuse.*.xml"');
    }
    foreach my $file (split("\n", $files)) {
        upload_logs("$file");
    }
    upload_logs("$f_stdout") if script_run "! [[ -e $f_stdout ]]";
    upload_logs("$f_stderr") if script_run "! [[ -e $f_stderr ]]";
    if (get_var('UPLOAD_REPORT_HTML')) {
        upload_logs("$f_report", timeout => 600)
          if script_run "! [[ -e $f_report ]]";
    }
}

sub pattern_count_in_file {

    #Find count and rules names of matched pattern
    my $self = $_[0];
    my $data = $_[1];
    my $pattern = $_[2];
    my @rules;
    my $count = 0;

    my @lines = split /\n|\r/, $data;
    for my $i (0 .. $#lines) {
        if ($lines[$i] =~ /$pattern/) {
            $count++;
            push(@rules, $lines[$i - 4]);
        }
    }

    #Returning by reference array of matched rules
    $_[3] = \@rules;
    return $count;
}

sub rules_count_in_file {

    #Find count of rules names matched name and status patterns
    my $self = $_[0];
    my $data = $_[1];
    my $pattern = $_[2];
    my $l_rules = $_[3];
    my @rules;
    my $count = 0;

    my @lines = split /\n|\r/, $data;
    my @a_rules = @$l_rules;

    for my $i (0 .. $#lines) {
        for my $j (0 .. $#a_rules) {
            if ($lines[$i] =~ /$a_rules[$j]/ and $lines[$i + 4] =~ /$pattern/) {
                $count++;
                push(@rules, $lines[$i]);
            }
        }
    }
    #Returning by reference array of matched rules
    $_[4] = \@rules;
    #Return -2 if found not correct count of rules
    if ($count == $#a_rules + 1) {
        return $count;
    }
    else {
        return -2;
    }
}

=comment
    OSCAP exit codes from https://github.com/OpenSCAP/openscap/blob/maint-1.3/utils/oscap-tool.h
    // standard oscap CLI exit statuses
    enum oscap_exitcode {
        OSCAP_OK             =   0, // successful exit
        OSCAP_ERROR          =   1, // an error occurred
        OSCAP_FAIL           =   2, // a process (e.g. scan or validation) failed
        OSCAP_ERR_FETCH      =   1, // cold not fetch input file (same as error for now)
        OSCAP_BADARGS        = 100, // bad commandline arguments
        OSCAP_BADMODULE      = 101, // unrecognized module
        OSCAP_UNIMPL_MOD     = 110, // module functionality not implemented
        OSCAP_UNIMPL         = 111, // functionality not implemented
        // end of list
        OSCAP_EXITCODES_END_ = 120  // any code returned shall not be higher than this
    };
=cut

sub oscap_security_guide_setup {

    select_console 'root-console';

    # Install packages
    zypper_call('in openscap-utils scap-security-guide', timeout => 180);

    # Record the pkgs' version for reference
    my $out = script_output("zypper se -s openscap-utils scap-security-guide");
    record_info("Pkg_ver", "openscap security guide packages' version:\n $out");

    # Set ds file
    set_ds_file();

    # Check the ds file information for reference
    my $f_ssg_ds = is_sle ? $f_ssg_sle_ds : $f_ssg_tw_ds;
    $out = script_output("oscap info $f_ssg_ds");
    record_info("oscap info", "\"# oscap info $f_ssg_ds\" returns:\n $out");

    # Check the oscap version information for reference
    $out = script_output("oscap -V");
    record_info("oscap version", "\"# oscap -V\" returns:\n $out");
    
    # If required ansible remediation
    if ($ansible_remediation == 1) {
        my $pkgs = 'ansible';

        unless (is_opensuse) {
            # Package'ansible' require PackageHub is available
            return unless is_phub_ready();
            add_suseconnect_product(get_addon_fullname('phub'));
        }
        zypper_call "in $pkgs sudo";
        # Record the pkgs' version for reference
        my $out = script_output("zypper se -s $pkgs");
        record_info("$pkgs Pkg_ver", "$pkgs packages' version:\n $out");
    }
}

=ansible return codes
0 = The command ran successfully, without any task failures or internal errors.
1 = There was a fatal error or exception during execution.
2 = Can mean any of:

    Task failures were encountered on some or all hosts during a play (partial failure / partial success).
    The user aborted the playbook by hitting Ctrl+C, A during a pause task with prompt.
    Invalid or unexpected arguments, i.e. ansible-playbook --this-arg-doesnt-exist some_playbook.yml.
    A syntax or YAML parsing error was encountered during a dynamic include, i.e. include_role or include_task.

3 = This used to mean “Hosts unreachable” per TQM, but that seems to have been redefined to 4. I’m not sure if this means anything different now.
4 = Can mean any of:

    Some hosts were unreachable during the run (login errors, host unavailable, etc). This will NOT end the run early.
    All of the hosts within a single batch were unreachable- i.e. if you set serial: 3 at the play level, and three hosts in a batch were unreachable. This WILL end the run early.
    A synax or parsing error was encountered- either in command arguments, within a playbook, or within a static include (import_role or import_task). This is a fatal error. 

5 = Error with the options provided to the command
6 = Command line args are not UTF-8 encoded
8 = A condition called RUN_FAILED_BREAK_PLAY occurred within Task Queue Manager.
99 = Ansible received a keyboard interrupt (SIGINT) while running the playbook- i.e. the user hits Ctrl+c during the playbook run.
143 = Ansible received a kill signal (SIGKILL) during the playbook run- i.e. an outside process kills the ansible-playbook command.
250 = Unexpected exception- often due to a bug in a module, jinja templating errors, etc.
255 = Unknown error, per TQM.
=cut

sub oscap_remediate {
    my ($self, $f_ssg_ds, $profile_ID) = @_;

    select_console 'root-console';

    # Verify mitigation mode
    # If doing ansible playbook remediation
    if ($ansible_remediation == 1) {
        my $path = '/usr/share/scap-security-guide/ansible/';
        my $inventory_file = "inventory.yml";
        my $inventory_file_fpath = $path . $inventory_file;
        my $playbook_fpath = $path . $profile_ID;
        # Create inventory file
        assert_script_run("echo -e \"all:\\n  hosts:\\n     localhost\\n  vars:\\n     ansible_connection: local\" > $inventory_file_fpath");
        my $ret
          = script_run("ansible-playbook -v -i $inventory_file_fpath $playbook_fpath > $f_stdout 2> $f_stderr", timeout => 600);
        record_info("Return=$ret", "ansible-playbook -v -i $inventory_file_fpath $playbook_fpath\" returns: $ret");
        if ($ret != 0 and $ret != 2 and $ret != 4) {
            record_info("returened $ret", 'remediation should be succeeded', result => 'fail');
            $self->result('fail');
        }
    }
    # If doing bash remediation
    else {
        my $ret
          = script_run("oscap xccdf eval --profile $profile_ID --remediate --oval-results --report $f_report $f_ssg_ds > $f_stdout 2> $f_stderr", timeout => 600);
        record_info("Return=$ret", "# oscap xccdf eval --profile $profile_ID --remediate\" returns: $ret");
        if ($ret != 0 and $ret != 2) {
            record_info('bsc#1194676', 'remediation should be succeeded', result => 'fail');
            $self->result('fail');
        }
    }
    if ($remediated == 0) {
        $remediated = 1;
        record_info('remediated', 'setting status remediated');
    }

    # Upload logs & ouputs for reference
    upload_logs_reports();
}

sub oscap_evaluate {
    my ($self, $f_ssg_ds, $profile_ID, $n_passed_rules, $n_failed_rules, $eval_match) = @_;
    select_console 'root-console';

    my $passed_rules_ref;
    my $failed_rules_ref;

    # Verify detection mode
    my $ret = script_run("oscap xccdf eval --profile $profile_ID --oval-results --report $f_report $f_ssg_ds > $f_stdout 2> $f_stderr", timeout => 600);
    if ($ret == 0 || $ret == 2) {
        record_info("Returned $ret", "oscap xccdf eval --profile $profile_ID --oval-results --report $f_report $f_ssg_ds > $f_stdout 2> $f_stderr");
        # Note: the system cannot be fully remediated in this test and some rules are verified failing
        my $data = script_output "cat $f_stdout";
        # For a new installed OS the first time remediate can permit fail
        if ($remediated == 0) {
            record_info('non remediated', 'before remediation more rules fails are expected');
            my $pass_count = pattern_count_in_file(1, $data, $f_pregex, $passed_rules_ref);
            record_info(
                "Passed rules count=$pass_count",
                "Pattern $f_pregex count in file $f_stdout is $pass_count. Matched rules:\n " . join "\n",
                @$passed_rules_ref
            );
            my $fail_count = pattern_count_in_file(1, $data, $f_fregex, $failed_rules_ref);
            record_info(
                "Failed rules count=$fail_count",
                "Pattern $f_fregex count in file $f_stdout is $fail_count. Matched rules:\n" . join "\n",
                @$failed_rules_ref
            );
        }
        else {
            #Verify remediated rules
            record_info('remediated', 'after remediation less rules are failing');

            #Verify failed rules
            my $ret_rcount = rules_count_in_file(1, $data, $f_fregex, $eval_match, $failed_rules_ref);
            my $failed_rules = $#$failed_rules_ref + 1;
            if ($ret_rcount == -2) {
                record_info(
                    "Failed check of failed rules",
                    "Pattern $f_fregex count in file $f_stdout is $failed_rules, expected $n_failed_rules. Matched rules:\n" . (join "\n",
                        @$failed_rules_ref) . "\nExpected rules:\n" . (join "\n",
                        @$eval_match),
                    result => 'fail'
                );
                $self->result('fail');
            }
            else {
                record_info(
                    "Passed check of failed rules",
                    "Check of $ret_rcount failed rules:\n" . (join "\n",
                        @$eval_match) . "\n in file $f_stdout. \nMatched rules:\n" . (join "\n",
                        @$failed_rules_ref)
                );
            }

            #Verify number of passed and failed rules
            my $pass_count = pattern_count_in_file(1, $data, $f_pregex, $passed_rules_ref);
            if ($pass_count != $n_passed_rules) {
                record_info(
                    "Failed check of passed rules count",
                    "Pattern $f_pregex count in file $f_stdout is $pass_count, expected $n_passed_rules. Matched rules:\n" . join "\n",
                    @$passed_rules_ref, result => 'fail'
                );
                $self->result('fail');
            }
            else {
                record_info(
                    "Passed check of passed rules count",
                    "Pattern $f_pregex count in file $f_stdout is $pass_count. Matched rules:\n" . join "\n",
                    @$passed_rules_ref
                );
            }
            my $fail_count = pattern_count_in_file(1, $data, $f_fregex, $failed_rules_ref);
            if ($fail_count != $n_failed_rules) {
                record_info(
                    "Failed check of failed rules count",
                    "Pattern $f_fregex count in file $f_stdout is $fail_count, expected $n_failed_rules. Matched rules: \n" . join "\n",
                    @$failed_rules_ref, result => 'fail'
                );
                $self->result('fail');
            }
            else {
                record_info(
                    "Passed check of failed rules count",
                    "Pattern $f_fregex count in file $f_stdout is $fail_count. Matched rules: \n" . join "\n",
                    @$failed_rules_ref
                );
            }
        }
    }
    else {
        record_info("errno=$ret", "# oscap xccdf eval --profile \"$profile_ID\" returns: $ret", result => 'fail');
        $self->result('fail');
    }

    # Upload logs & ouputs for reference
    upload_logs_reports();
}

sub oscap_evaluate_remote {
    my ($self, $f_ssg_ds, $profile_ID) = @_;

    select_console 'root-console';

    add_grub_cmdline_settings('ignore_loglevel', update_grub => 1);
    power_action('reboot', textmode => 1);
    reconnect_mgmt_console if is_pvm;
    $self->wait_boot(textmode => 1);

    select_console 'root-console';

    # Verify detection mode with remote
    my $ret = script_run(
        "oscap xccdf eval --profile $profile_ID --oval-results --fetch-remote-resources --report $f_report $f_ssg_ds > $f_stdout 2> $f_stderr",
        timeout => 3000
    );
    record_info("Return=$ret",
        "# oscap xccdf eval --fetch-remote-resources --profile $profile_ID\" returns: $ret"
    );
    if ($ret == 137) {
        record_info('bsc#1194724', "eval returned $ret", result => 'fail');
    }

    # Upload logs & ouputs for reference
    upload_logs_reports();
}


1;
