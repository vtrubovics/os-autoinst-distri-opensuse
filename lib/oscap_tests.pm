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
use Utils::Architectures;
use registration qw(add_suseconnect_product get_addon_fullname is_phub_ready);
use List::MoreUtils qw(uniq);
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);
use List::Compare;
use Config::Tiny;
use Module::Runtime qw(use_module);

our @EXPORT = qw(
  $profile_ID
  $ansible_profile_ID
  $f_ssg_sle_ds
  $f_ssg_sle_xccdf
  $f_ssg_ds
  $ssg_sle_ds
  $ssg_sle_xccdf
  $ssg_tw_ds
  $ssg_tw_xccdf
  $f_stdout
  $f_stderr
  $f_report
  $remediated
  $ansible_remediation
  $sle_version
  $compliance_as_code_path
  set_ds_file
  set_ds_file_name
  upload_logs_reports
  pattern_count_in_file
  cce_ids_in_file
  oscap_security_guide_setup
  oscap_remediate
  oscap_evaluate
  oscap_evaluate_remote
  bash_expected_rules
  bash_miss_rem_pattern
  bash_rem_pattern
  bash_script_stig
  bash_script_stig
  bash_script_cis
  bash_script_pci_dss
  bash_script_pci_dss_4
  bash_script_hipaa
  bash_script_anssi_bp28_high
  bash_script_anssi_bp28_enhanced
  bash_script_cis_server_l1
  bash_script_cis_workstation_l2
  bash_script_anssi_bp28_intermediary
  bash_script_anssi_bp28_minimal
  bash_script_cis_workstation_l1
  bash_script_standart
  get_bash_expected_results
  profile_id_to_bash_script
);

# The file names of scap logs and reports
our $f_stdout = 'stdout';
our $f_stderr = 'stderr';
our $f_vlevel = 'ERROR';
our $f_report = 'report.html';
our $f_pregex = '\\bpass\\b';
our $f_fregex = '\\bfail\\b';
our $bash_miss_rem_pattern = 'FIX FOR THIS RULE.+IS MISSING';
our $bash_rem_pattern = 'Remediating rule';
our $ansible_exclusions;
our $ansible_playbook_modified = 0;
our $compliance_as_code_path;

# Set default value for 'scap-security-guide' ds file
our $f_ssg_sle_ds = '/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml';
our $f_ssg_tw_ds = '/usr/share/xml/scap/ssg/content/ssg-opensuse-ds.xml';
our $ssg_sle_ds = 'ssg-sle15-ds.xml';
our $ssg_tw_ds = 'ssg-opensuse-ds.xml';

our $f_ssg_sle_xccdf = '/usr/share/xml/scap/ssg/content/ssg-sle15-xccdf.xml';
our $f_ssg_tw_xccdf = '/usr/share/xml/scap/ssg/content/ssg-opensuse-xccdf.xml';
our $ssg_sle_xccdf = 'ssg-sle15-xccdf.xml';
our $ssg_tw_xccdf = 'ssg-opensuse-xccdf.xml';
our $f_ssg_ds;

# Profile IDs
our $profile_ID;
our $ansible_profile_ID;
# Priority High:
our $profile_ID_sle_stig = 'xccdf_org.ssgproject.content_profile_stig';
our $profile_ID_sle_cis = 'xccdf_org.ssgproject.content_profile_cis';
our $profile_ID_sle_pci_dss = 'xccdf_org.ssgproject.content_profile_pci-dss';
our $profile_ID_sle_pci_dss_4 = 'xccdf_org.ssgproject.content_profile_pci-dss-4';
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
our $ansible_playbook_sle_pci_dss_4 = "-playbook-pci-dss-4.yml";
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

# BASH scripts
our $bash_script_stig = "-script-stig.sh";
our $bash_script_cis = "-script-cis.sh";
our $bash_script_pci_dss = "-script-pci-dss.sh";
our $bash_script_pci_dss_4 = "-script-pci-dss-4.sh";
# Only sle-15
our $bash_script_hipaa = "-script-hipaa.sh";

our $bash_script_anssi_bp28_high = "-script-anssi_bp28_high.sh";
# Priority Medium:
our $bash_script_anssi_bp28_enhanced = "-script-anssi_bp28_enhanced.sh";
our $bash_script_cis_server_l1 = "-script-cis_server_l1.sh";
our $bash_script_cis_workstation_l2 = "-script-cis_workstation_l2.sh";
# Priority Low:
our $bash_script_anssi_bp28_intermediary = "-script-anssi_bp28_intermediary.sh";
our $bash_script_anssi_bp28_minimal = "-script-anssi_bp28_minimal.sh";
our $bash_script_cis_workstation_l1 = "-script-cis_workstation_l1.sh";
our $bash_script_standart = "opensuse-script-standard.sh";

# The OS status of remediation: '0', not remediated; '1', remediated
our $remediated = 0;

# Is it ansible remediation: '0', bash remediation; '1' ansible remediation
our $ansible_remediation = 0;

# Variables $use_production_files and $remove_rules_missing_fixes are fetched from configuration file located in:
#https://gitlab.suse.de/seccert-public/compliance-as-code-compiled/-/blob/main/content/openqa_config.conf
# If set to 1 - tests will use files from scap-security-guide package
# If set to 0 - tests will use files from https://gitlab.suse.de/seccert-public/compliance-as-code-compiled repository
our $use_production_files = 0;

# Option configures to use or not functionality to remove from DS and ansible file rules for which do not have remediations
# If set to 1 - rules for which do not have remediations will be removed from DS and ansible file rules for which do not have remediations
# If set to 0 - no changes done.
our $remove_rules_missing_fixes = 1;

# Get sle version "sle12" or "sle15"
our $sle_version = 'sle' . get_required_var('VERSION') =~ s/([0-9]+).*/$1/r;

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
    $f_ssg_sle_xccdf =
      '/usr/share/xml/scap/ssg/content/ssg-sle' . "$version" . '-xccdf.xml';
}
sub set_ds_file_name {

    # Set the ds file for separate product, e.g.,
    # for SLE15 the ds file is "ssg-sle15-ds.xml";
    # for SLE12 the ds file is "ssg-sle12-ds.xml"; 
    # for Tumbleweed the ds file is "ssg-opensuse-ds.xml"
    my $version = get_required_var('VERSION') =~ s/([0-9]+).*/$1/r;
    $ssg_sle_ds =
      'ssg-sle' . "$version" . '-ds.xml';
    $ssg_sle_xccdf =
      'ssg-sle' . "$version" . '-xccdf.xml';
}

# Replace original ds file whith downloaded from repository
sub replace_ds_file {
    my $self = $_[0];
    my $ds_file_name = $_[1];
    my $url = "https://gitlab.suse.de/seccert-public/compliance-as-code-compiled/-/raw/main/content/";
    
    download_file_from_https_repo($url, $ds_file_name);
    # Remove original ds file
    assert_script_run("rm $f_ssg_sle_ds");
    # Copy downloaded file to correct location
    assert_script_run("cp $ds_file_name $f_ssg_sle_ds");
    record_info("Copied ds file", "Copied file $ds_file_name to $f_ssg_sle_ds");
}
# Replace original xccdf file whith downloaded from repository
sub replace_xccdf_file {
    my $self = $_[0];
    my $xccdf_file_name = $_[1];
    my $url = "https://gitlab.suse.de/seccert-public/compliance-as-code-compiled/-/raw/main/content/";
    
    download_file_from_https_repo($url, $xccdf_file_name);
    # Remove original xccdf file
    assert_script_run("rm $f_ssg_sle_xccdf");
    # Copy downloaded file to correct location
    assert_script_run("cp $xccdf_file_name $f_ssg_sle_xccdf");
    record_info("Copied xccdf file", "Copied file $xccdf_file_name to $f_ssg_sle_xccdf");
}

# Replace original ansible file whith downloaded from repository
sub replace_ansible_file {
    my $self = $_[0];
    my $ansible_file_name = $_[1];
    my $ansible_file_path = $_[2];
    my $url = "https://gitlab.suse.de/seccert-public/compliance-as-code-compiled/-/raw/main/ansible/";

    download_file_from_https_repo($url, $ansible_file_name);
    # Remove original ansible file
    assert_script_run("rm $full_ansible_file_path");
    # Copy downloaded file to correct location
    assert_script_run("cp $ansible_file_name $full_ansible_file_path");
    record_info("Copied ansible file", "Copied file $ansible_file_name to $full_ansible_file_path");
}

# Download and pharse ansible exclusions file from repository
sub get_ansible_exclusions {
    my $self = $_[0];
    my $ansible_exclusions_file_name = "ansible_exclusions.txt";
    my $ansible_file_path = '/usr/share/scap-security-guide/ansible/' . $ansible_profile_ID;
    my $url = "https://gitlab.suse.de/seccert-public/compliance-as-code-compiled/-/raw/main/ansible/";
    
    download_file_from_https_repo($url, $ansible_exclusions_file_name);
    my $data = script_output "cat $ansible_exclusions_file_name";
    my @lines = split /\n|\r/, $data;
    my $found = 0;
    my @strings;
    my $exclusions;
    my $fprofile_ID = $profile_ID . " "; # Fix for profile names having extensions 

    record_info("Looking for exclusions", "Looking for exclusions for profile $profile_ID");
    for my $i (0 .. $#lines) {
        if ($lines[$i] =~ /$fprofile_ID/) {
            @strings = split /\s+/, $lines[$i];
            $exclusions = $strings[1];
            $exclusions =~ s/\"//g;
            $found = 1;
            record_info("Found exclusions", "Found exclusions:\n$exclusions\nfor profile $strings[0]");
            last;
        }
    }
    # If exclusion are not found for playbook - ignore_errors: true are added to all tasks in playbook
    if ($found == 0 and $ansible_playbook_modified == 0){
        record_info("Did not found exclusions", "Did not found exclusions for profile $profile_ID");
        my $insert_cmd = "sed -i \'s/      tags:/      ignore_errors: true\\n      tags:/g\' $ansible_file_path";
        assert_script_run("$insert_cmd");
        record_info("Insеrted ignore_errors", "Inserted \"ignore_errors: true\" for every tag in playbook. CMD:\n$insert_cmd");
        $ansible_playbook_modified = 1;
        }
    #Returning by reference exclusions string
    $_[1] = $exclusions;
    return $found;
}
# Download and pharse bash exclusions file from repository
sub get_bash_exclusions {
    my $self = $_[0];
    my $bash_exclusions_file_name = "bash_exclusions.txt";
    $url = "https://gitlab.suse.de/seccert-public/compliance-as-code-compiled/-/raw/main/bash/";

    download_file_from_https_repo($url, $bash_exclusions_file_name);
   
    my $data = script_output "cat $bash_exclusions_file_name";
    my @lines = split /\n|\r/, $data;
    my $found = 0;
    my @strings;
    my $exclusions;
    record_info("Looking for bash exclusions", "Looking for exclusions for profile $profile_ID");
    for my $i (0 .. $#lines) {
        if ($lines[$i] =~ /$profile_ID/) {
            @strings = split /\s+/, $lines[$i];
            $exclusions = $strings[1];
            $exclusions =~ s/\"//g;
            $found = 1;
            record_info("Found exclusions", "Found exclusions $exclusions for profile $profile_ID");
            last;
        }
    }
    if ($found == 0){
        record_info("Did not found exclusions", "Did not found bash exclusions for profile $profile_ID");
        }
    #Returning by reference exclusions string
    $_[1] = $exclusions;
    return $found;
}
# Convert Profile ID to bash remediation script name
sub profile_id_to_bash_script {
    my $self = $_[0];
    my $profile_id = $_[1];

    my @lines = split /_profile_/, $profile_id;
    my $os = is_sle ? $sle_version : "opensuse";
    my $profile = is_sle ? $lines[1] : "standard";
    my $bash_name = $os . "-script-" . $profile . ".sh";

    return $bash_name;
}
# Download and pharse bash remediation file from repository and returns expected results
sub get_bash_expected_results {
    my $self = $_[0];
    my $pattern = $_[1];
    my $rem_pattern = $_[2];
    my $bash_rem_script = $_[3];
    my @rules = ();
    my @rem_rules = ();
    my @strings = ();
    my $data = ;
    my $url = "https://gitlab.suse.de/seccert-public/compliance-as-code-compiled/-/raw/main/bash/";

    download_file_from_https_repo($url, $bash_rem_script);

    my @lines = split /\n|\r/, $data;

    for my $i (0 .. $#lines) {
        if ($lines[$i] =~ /$pattern/) {
            @strings = split /\'|\./, $lines[$i];
            push(@rules, $strings[3]);
        }
        if ($lines[$i] =~ /$rem_pattern/) {
            @strings = split /\'|\./, $lines[$i];
            push(@rem_rules, $strings[3]);
        }
    }
    # Returning by reference expected data
    record_info("List of expected failed rules", "List of expected failed rules:\n" . join "\n", @rules);

    $_[4] = \@rules;
    $_[5] = \@rem_rules;

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
    # Check if list of files returned correctly
    if (defined $files) {
        foreach my $file (split("\n", $files)) {
            upload_logs("$file") if script_run "! [[ -e $file ]]";
        }
    }
    upload_logs("$f_stdout") if script_run "! [[ -e $f_stdout ]]";
    upload_logs("$f_stderr") if script_run "! [[ -e $f_stderr ]]";
    
    if (get_var('UPLOAD_REPORT_HTML')) {
        upload_logs("$f_report", timeout => 600)
          if script_run "! [[ -e $f_report ]]";
    }
}
sub download_file_from_https_repo {
    # downloads file from provided url
    my $url = $_[0];
    my $file_name = $_[1];
    my $full_url = "$url" . "$file_name";
    
    my $FULL_URL = get_var("FILE", "$full_url");

    assert_script_run("wget --no-check-certificate $FULL_URL");
    assert_script_run("chmod 774 $file_name");
    record_info("Downloaded file", "Downloaded file $file_name from $FULL_URL");
}
sub pattern_count_in_file {

    #Find count and rules names of matched pattern
    my $self = $_[0];
    my $data = $_[1];
    my $pattern = $_[2];
    my @rules = ();
    my @rules_cce = ();
    my @rules_ids = ();
    my $count = 0;
    my @nlines;
    my @lines = split /\n|\r/, $data;
    for my $i (0 .. $#lines) {
        if ($lines[$i] =~ /$pattern/) {
            $count++;
            $lines[$i - 2] =~ s/\s+//g; # remove whitespace from cce_id
            $lines[$i - 4] =~ s/\s+//g; # remove whitespace from rule id
            @nlines = split /\./, $lines[$i - 4];
            push(@rules_ids, $nlines[2]); # push rule id to list
            $nlines[2] .= ", " . $lines[$i - 2]; # add cce id
            push(@rules_cce, $lines[$i - 2]);# push rule cce id to list
            push(@rules, $nlines[2]) if ($i >= 4); # push rule id and rule cce id to list
        }
    }
    #Returning by reference array of matched rules
    $_[3] = \@rules;
    $_[4] = \@rules_cce;
    $_[5] = \@rules_ids;
    return $count;
}

sub cce_ids_in_file {

    #Find all unique CCE IDs by provided pattern
    my $self = $_[0];
    my $data = $_[1];
    my $pattern = $_[2];
    my @cces;
    my $cce;

    my @lines = split /\n|\r/, $data;
    for my $i (0 .. $#lines){
        if($lines[$i] =~ /($pattern)/){
            $cce = $1;
            push(@cces, $cce);
        }
    }
    # Saving only unique CCE IDs
    my @unique_cces = uniq @cces;
    # Returning by reference array of CCE IDs
    $_[3] = \@unique_cces;
    return $#unique_cces + 1;
}

sub modify_ds_ansible_files {
    # Removes bash and ansible excluded and not having fixes rules from DS and playbook files
    my $self = $_[0];
    my $in_file_path = $_[1];
    my $bash_pattern = "missing a bash fix";
    my $ansible_pattern = "missing a ansible fix";
    my $data;
    my @bash_rules = ();
    my @ansible_rules = ();
    my $i = 0;
    my $bash_fix_missing = "bash_fix_missing.txt";
    my $ansible_fix_missing = "ansible_fix_missing.txt";
    my $ds_unselect_rules_script = "ds_unselect_rules.sh";

    $data = script_output("cat $in_file_path");
    
    my @lines = split /\n|\r/, $data;

    for  ($i = 0; $i <= $#lines;) { #(0 .. $#lines)
        if ($lines[$i] =~ /$bash_pattern/) {
            $i++;
            until ($lines[$i] =~ /\*\*\*/) {
                $lines[$i] =~ s/\s+|\r|\n//g; #remowe unneded symbols
                push(@bash_rules, $lines[$i]);
                $i++;
            }
        }
        if ($lines[$i] =~ /$ansible_pattern/) {
            $i++;
            until ($lines[$i] =~ /\*\*\*/) {
                $lines[$i] =~ s/\s+|\r|\n//g; #remowe unneded symbols
                push(@ansible_rules, $lines[$i]);
                $i++;
            }
        }
    $i++;
    }
    record_info("Got rules from lists", "Got rules from lists from  $in_file_path\nBash pattern:\n$bash_pattern\nAnsible pattern:\n $ansible_pattern");

    if ($#bash_rules > 0 and $ansible_remediation == 0) {
        record_info("Bash rules missing fix", "Bash rules missing fix:\n" . join "\n",
                    @bash_rules
                    );
    }
    if ($#ansible_rules > 0 and $ansible_remediation == 1) {
        record_info("Ansible rules missing fix", "Ansible rules missing fix:\n" . join "\n",
                    @ansible_rules
                    );
    }

   if ($ansible_remediation == 1) {
        my $ansible_f = join "\n",  @ansible_rules;
        assert_script_run("printf \"$ansible_f\" > \"$ansible_fix_missing\"");
        
        my $ret_get_ansible_exclusions = 0;
        my $ansible_exclusions;

        # Get rule exclusions for ansible playbook
        $ret_get_ansible_exclusions
          = get_ansible_exclusions (1, $ansible_exclusions);
        # Write exclusions to the file 
        if ($ret_get_ansible_exclusions == 1) {
            $ansible_exclusions =~ s/\,/\n/g;
            assert_script_run("printf \"\n$ansible_exclusions\" >> \"$ansible_fix_missing\"");
            record_info("Writing ansible exceptions to file", "Writing ansible exclusions:\n$ansible_exclusions\n\nto file: $ansible_fix_missing");
        }
        # Diasble excluded and fix missing rules in ds file
        my $unselect_cmd = "sh $compliance_as_code_path/tests/$ds_unselect_rules_script $f_ssg_sle_ds $ansible_fix_missing";
        assert_script_run("$unselect_cmd", timeout => 600);
        assert_script_run("rm $f_ssg_sle_ds");
        assert_script_run("cp /tmp/$ssg_sle_ds $f_ssg_sle_ds");
        record_info("Diasble excluded and fix missing rules in ds file", "Command $unselect_cmd");
        upload_logs("$ansible_fix_missing") if script_run "! [[ -e $ansible_fix_missing ]]";
        # Replace ansible file with located on https://gitlab.suse.de/seccert-public/compliance-as-code-compiled
        replace_ansible_file (1, $ansible_profile_ID, '/usr/share/scap-security-guide/ansible/');

        # Generate new playbook without exclusions and fix_missing rules 
        my $playbook_fpath = '/usr/share/scap-security-guide/ansible/' . $ansible_profile_ID;
        my $playbook_gen_cmd = "oscap xccdf generate fix --profile $profile_ID --fix-type ansible $f_ssg_sle_ds > playbook.yml";
        assert_script_run("$playbook_gen_cmd");
        record_info("Generated playbook", "Command $playbook_gen_cmd");
        assert_script_run("rm $playbook_fpath");
        assert_script_run("cp playbook.yml $playbook_fpath");
        record_info("Replaced playbook", "Replaced playbook $playbook_fpath with generated playbook.yml");
        upload_logs("$playbook_fpath") if script_run "! [[ -e $playbook_fpath ]]";
        # After playbook is regenereates need to modify it on next get_ansible_exclusions call
        $ansible_playbook_modified = 0;
    }
    else {
        my $bash_f = join "\n",  @bash_rules;
        assert_script_run("printf \"$bash_f\" > \"$bash_fix_missing\"");

        my $ret_get_bash_exclusions = 0;
        my $bash_exclusions;

        # Get rule exclusions for bash playbook
        $ret_get_bash_exclusions
          = get_bash_exclusions (1, $bash_exclusions);
        # Write exclusions to the file 
        if ($ret_get_bash_exclusions == 1) {
            $bash_exclusions =~ s/\,/\n/g;
            assert_script_run("printf \"\n$bash_exclusions\" >> \"$bash_fix_missing\"");
            record_info("Writing bash exceptions to file", "Writing bash exclusions:\n$bash_exclusions\n\nto file: $bash_fix_missing");
        }
        # Diasble excluded and fix missing rules in ds file
        my $unselect_cmd = "sh $compliance_as_code_path/tests/$ds_unselect_rules_script $f_ssg_sle_ds $bash_fix_missing";
        assert_script_run("$unselect_cmd");
        assert_script_run("rm $f_ssg_sle_ds");
        assert_script_run("cp /tmp/$ssg_sle_ds $f_ssg_sle_ds");
        record_info("Diasble excluded and fix missing rules in ds file", "Command $unselect_cmd");
        upload_logs("$bash_fix_missing") if script_run "! [[ -e $bash_fix_missing ]]";
     }
    upload_logs("$f_ssg_sle_ds") if script_run "! [[ -e $f_ssg_sle_ds ]]";

    my $output_full_path = script_output("pwd");
    $output_full_path =~ s/\r|\n//g;
    my $bash_file_full_path = "$output_full_path/$bash_fix_missing";
    my $ansible_file_full_path = "$output_full_path/$ansible_fix_missing";
    record_info("Files paths for missing rules ", "Bash file path:\n$bash_file_full_path\nAnsible file path:\n $ansible_file_full_path");

}

sub generate_mising_rules {
    # Generate text file that contains rules that missing implimentation for profile
    my $self = $_[0];
    my $profile = $_[1];
    my $output_file = "missing_rules.txt";

    assert_script_run("alias python=python3");
    assert_script_run("cd $compliance_as_code_path");
    assert_script_run("source .pyenv.sh");
    my $env = script_output("env | grep PYTHONPATH");
    record_info("exported PYTHONPATH", "export $env");
    my $cmd = "python3 build-scripts/profile_tool.py stats --missing --skip-stats --profile $profile --benchmark $f_ssg_sle_xccdf --format plain > $output_file";
    assert_script_run("$cmd");
    record_info("Generated file $output_file", "generate_mising_rules Input file $f_ssg_sle_xccdf/n Command:\n$cmd");
    assert_script_run("cp $output_file /root");
    assert_script_run("cd /root");
    my $output_full_path = script_output("pwd");
    $output_full_path =~ s/\r|\n//g;
    $output_full_path .= "/$output_file";

    return $output_full_path;
}

sub get_cac_code {
    # Get the code for the ComplianceAsCode by cloning its repository
    my $cac_dir = "src/content";
    my $git_repo = "https://github.com/ComplianceAsCode/content.git";
    my $git_clone_cmd = "git clone " . $git_repo . " $cac_dir";
    
    zypper_call("in git-core python3");
    assert_script_run("mkdir src");
    assert_script_run("rm -r $cac_dir", quiet => 1) if (-e "$cac_dir");
    assert_script_run('git config --global http.sslVerify false', quiet => 1);
    assert_script_run("set -o pipefail ; $git_clone_cmd", quiet => 1);

    $compliance_as_code_path = script_output("pwd");
    $compliance_as_code_path =~ s/\r|\n//g;
    $compliance_as_code_path .= "/$cac_dir";

    record_info("Cloned ComplianceAsCode", "Cloned repo $git_repo to folder: $compliance_as_code_path");
    assert_script_run('pip3 --quiet install --upgrade pip', timeout => 600);
    assert_script_run("pip3 --quiet install jinja2", timeout => 600);
    assert_script_run("pip3 --quiet install PyYAML", timeout => 600);
    assert_script_run("pip3 --quiet install pytest", timeout => 600);
    assert_script_run("pip3 --quiet install pytest-cov", timeout => 600);
    assert_script_run("pip3 --quiet install Jinja2", timeout => 600);
    assert_script_run("pip3 --quiet install setuptools", timeout => 600);
    assert_script_run("pip3 --quiet install ninja", timeout => 600);
    return $compliance_as_code_path;
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

sub get_tests_config {
    # Get the tests configuration file from repository
    my $config_file_name = "openqa_config.conf";
    my $url = "https://gitlab.suse.de/seccert-public/compliance-as-code-compiled/-/raw/main/content/";

    download_file_from_https_repo($url, $config_file_name);

    my $config_file_path = script_output("pwd");
    $config_file_path =~ s/\r|\n//g;
    $config_file_path .= "/$config_file_name";
    
    my $data = script_output ("cat $config_file_path");
    my $config = Config::Tiny->new;
    $config = Config::Tiny->read_string("$data");
    my $err = $config::Tiny::errstr;
    if ($err eq ""){
        $use_production_files = $config->{tests_config}->{use_production_files};
        $remove_rules_missing_fixes = $config->{tests_config}->{remove_rules_missing_fixes};
        record_info("Set test configuration", "Set test configuration from file $config_file_path\n use_production_files = $use_production_files\n  remove_rules_missing_fixes = $remove_rules_missing_fixes");
    }
    else {
        record_info("Tiny->read error", "Config::Tiny->read( $config_file_path )returened error:\n$err");
    }
    return $config_file_path;
}

sub get_test_expected_results {
    my $n_passed_rules;
    my $eval_match = ();
    my $found = -1;
    my $type = "";
    my $arch = "";
    
    if ($ansible_remediation == 1) {
        $type = 'ansible';
    }
    else {
        $type = 'bash';
    }
    if (is_s390x) { $arch = "s390x";}
    if (is_aarch64 or is_arm) { $arch = "aarch64";}
    if (is_ppc64le) { $arch = "ppc";}
    if (is_x86_64) { $arch = "x86_64";}
    # $sle_version and $profile_ID are global varables
    my $passed_rules = $sle_version . "-passed_rules";
    my $exp_fail_list_name = $sle_version . "-exp_fail_list";
    my $expected_results_file_name = "openqa_tests_expected_results.yaml";
    my $url = "https://gitlab.suse.de/seccert-public/compliance-as-code-compiled/-/raw/main/content/";

    download_file_from_https_repo($url, $expected_results_file_name);
    upload_logs("$expected_results_file_name") if script_run "! [[ -e $expected_results_file_name ]]";
    my $data = script_output ("cat $expected_results_file_name");

    # Pharse the expected results
    my $module = use_module("YAML::Tiny");
    my $expected_results = YAML::Tiny->read_string( "$data" );
    record_info("Looking expected results", "Looking expected results for \nprofile_ID: $profile_ID\ntype: $type\narch: $arch");

    $n_passed_rules  = $expected_results->[0]->{$profile_ID}->{$type}->{$arch}->{$passed_rules};
    $eval_match  = $expected_results->[0]->{$profile_ID}->{$type}->{$arch}->{$exp_fail_list_name};

    if (defined $n_passed_rules) {
        record_info("Got expected results", "Got expected results for \nprofile_ID: $profile_ID\ntype: $type\narch: $arch\nNumber of passed rules: $n_passed_rules\n List of expected to fail rules:\n " . join "\n", @$eval_match);
        $found = 1;
        if (defined $eval_match) {
            $_[1] = $eval_match;
        }
        else {
            my @eval_match = ();
            $_[1] = \@eval_match;
        }    }
    else {
        record_info("No expected results", "No expected results found in \nfile: $expected_results_file_name\n for profile_ID: $profile_ID\ntype: $type\narch: $arch\n Using results defined in the test file.");
        $n_passed_rules = -1;
        my @eval_match = ();
        $_[1] = \@eval_match;
    }

    $_[0] = $n_passed_rules;
    return $found;
}

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
    $f_ssg_ds = is_sle ? $f_ssg_sle_ds : $f_ssg_tw_ds;
    $out = script_output("oscap info $f_ssg_ds");
    record_info("oscap info", "\"# oscap info $f_ssg_ds\" returns:\n $out");

    # Check the oscap version information for reference
    $out = script_output("oscap -V");
    record_info("oscap version", "\"# oscap -V\" returns:\n $out");

    # Get the tests configuration file from repository
    get_tests_config();
    
    # Replace original ds and xccdf files whith downloaded from local repository
    set_ds_file_name();
    
    if ($use_production_files == 0){
        my $ds_file_name = is_sle ? $ssg_sle_ds : $ssg_tw_ds;
        replace_ds_file(1, $ds_file_name);
        
        my $xccdf_file_name = is_sle ? $ssg_sle_xccdf : $ssg_tw_xccdf;
        replace_xccdf_file(1, $xccdf_file_name);
    }

    unless (is_opensuse) {
        # Some Packages require PackageHub repo is available
        return unless is_phub_ready();
        add_suseconnect_product(get_addon_fullname('phub'));
        # On SLES 12 ansible packages require depencies located in sle-module-public-cloud
        add_suseconnect_product(get_addon_fullname('pcm'), (is_sle('<15') ? '12' : undef)) if is_sle('<15');
        # Products needed for cpanm install
        add_suseconnect_product(get_addon_fullname('desktop'));
        add_suseconnect_product(get_addon_fullname('tcm'));
    }
    # Installing cpanm and perl library YAML::Tiny for expected results pharsing
    zypper_call "in cpanm";
    record_info("Install cpanm", "Installed cpanm");
    assert_script_run('cpanm YAML::Tiny', timeout => 300);
    record_info("Install YAML::Tiny", "Installed YAML::Tiny for expected results pharsing");

    # If required ansible remediation
    if ($ansible_remediation == 1) {
        my $pkgs = 'ansible';
        # Need to update SLES to fix issues with STIG playbook
        record_info("Update", "Updaiting SLES");
        zypper_call("up", timeout => 1800);
        zypper_call "in $pkgs sudo";
        # Record the pkgs' version for reference
        my $out = script_output("zypper se -s $pkgs");
        record_info("$pkgs Pkg_ver", "$pkgs packages' version:\n $out");
        #install ansible.posix
        assert_script_run("ansible-galaxy collection install ansible.posix");
    }
    if ($remove_rules_missing_fixes == 1){
        # Get the code for the ComplianceAsCode by cloning its repository
        get_cac_code ();
        # Generate text file that contains rules that missing implimentation for profile
        my $mising_rules_full_path = generate_mising_rules (1, $profile_ID);

        # Get bash and ansible rules lists from data based on provided 
        modify_ds_ansible_files(1, $mising_rules_full_path);
    }
    else {
        record_info("Do not modify DS or Ansible files", "Do not modify DS or Ansible files because remove_rules_missing_fixes = $remove_rules_missing_fixes");
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
    my ($self) = @_;
    select_console 'root-console';
    
    # Verify mitigation mode
    # If doing ansible playbook remediation
    if ($ansible_remediation == 1) {
        # my $playbook_content = script_output ("grep -e CCE $playbook_fpath", 120);
        # my $pattern ="CCE-\\d+-\\d";
        # my $cce_ids_array_ref;
        my $playbook_fpath = '/usr/share/scap-security-guide/ansible/' . $ansible_profile_ID;
        my $ret;
        my $start_time;
        my $end_time;
        my $execution_times = "execution_times.txt";
        my $execution_time;
        my $line;
        my $ret_get_exclusions = 0;
        my $ansible_exclusions;
        my $script_cmd;

        # Get rule exclusions for ansible playbook
        $ret_get_exclusions
          = get_ansible_exclusions (1, $ansible_exclusions);
        
        # Get array of CCE IDs
        # cce_ids_in_file (1, $playbook_content, $pattern, $cce_ids_array_ref );
        $start_time = clock_gettime(CLOCK_MONOTONIC);
        $script_cmd = "ansible-playbook -i \"localhost,\" -c local $playbook_fpath";
        
        # If found exclusions for current profile will add tem to command line
        # if ($ret_get_exclusions != 0) {
            # $script_cmd .= " --skip-tags " . $ansible_exclusions;
        # }
        $script_cmd .= "  >> $f_stdout 2>> $f_stderr";
        
        $ret
          = script_run($script_cmd, timeout => 3200);
        record_info("Return=$ret", "$script_cmd  returned: $ret");
        $end_time = clock_gettime(CLOCK_MONOTONIC);
        $execution_time = $end_time - $start_time;

        $line = "playbook execution time: $execution_time";
        script_run("echo $line >> $execution_times");
        record_info("Time info", "$line");
        if ($ret != 0 and $ret != 2 and $ret != 4) {
            record_info("Returened $ret", 'remediation should be succeeded', result => 'fail');
            $self->result('fail');
        }

        # Upload only stdout logs
        upload_logs("$f_stdout") if script_run "! [[ -e $f_stdout ]]";
        upload_logs("$f_stderr") if script_run "! [[ -e $f_stderr ]]";
        upload_logs("$execution_times") if script_run "! [[ -e $execution_times ]]";
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
        # Upload logs & ouputs for reference
        upload_logs_reports();
   }
    if ($remediated == 0) {
        $remediated = 1;
        record_info('remediated', 'setting status remediated');
    }
}

sub oscap_evaluate {
    my ($self, $n_passed_rules, $n_failed_rules, $eval_match) = @_;
    select_console 'root-console';

    my $passed_rules_ref;
    my $failed_rules_ref;
    my $passed_cce_rules_ref;
    my $failed_cce_rules_ref;
    my $failed_id_rules_ref;
    my $lc;
    my @Ronly;
    my $fail_count;
    my $pass_count;
    my $expected_pass_count;
    my $expected_eval_match;
    my $ret_expected_results;
    
    # Verify detection mode
    my $ret = script_run("oscap xccdf eval --profile $profile_ID --oval-results --report $f_report $f_ssg_ds > $f_stdout 2> $f_stderr", timeout => 600);
    if ($ret == 0 || $ret == 2) {
        record_info("Returned $ret", "oscap xccdf eval --profile $profile_ID --oval-results --report $f_report $f_ssg_ds > $f_stdout 2> $f_stderr");
        # Note: the system cannot be fully remediated in this test and some rules are verified failing
        my $data = script_output "cat $f_stdout";
        # For a new installed OS the first time remediate can permit fail
        if ($remediated == 0) {
            record_info('non remediated', 'before remediation more rules fails are expected');
            $pass_count = pattern_count_in_file(1, $data, $f_pregex, $passed_rules_ref, $passed_cce_rules_ref);
            record_info(
                "Passed rules count=$pass_count",
                "Pattern $f_pregex count in file $f_stdout is $pass_count. Matched rules:\n " . join "\n",
                @$passed_rules_ref
            );
            $fail_count = pattern_count_in_file(1, $data, $f_fregex, $failed_rules_ref, $failed_cce_rules_ref);
            record_info(
                "Failed rules count=$fail_count",
                "Pattern $f_fregex count in file $f_stdout is $fail_count. Matched rules:\n" . join "\n",
                @$failed_rules_ref
            );
        }
        else {
            #Verify remediated rules
            $ret_expected_results = get_test_expected_results($expected_pass_count, $expected_eval_match);
            # Found expected results in yaml file 
            if ($ret_expected_results == 1){
                $n_passed_rules = $expected_pass_count;
                $n_failed_rules = @$expected_eval_match;
                $eval_match = $expected_eval_match;
            }
            record_info('remediated', 'after remediation less rules are failing');
            #Verify failed rules
            $fail_count = pattern_count_in_file(1, $data, $f_fregex, $failed_rules_ref, $failed_cce_rules_ref, $failed_id_rules_ref);
            my $failed_rules = $#$failed_id_rules_ref + 1;
            
            $lc = List::Compare->new('-u', \@$failed_id_rules_ref, \@$eval_match);
            my @intersection = $lc->get_intersection; # list of rules found in both lists
            my @lonly = $lc->get_Lonly; # list of rules found only in left list (actual results)
            my $intersection_count = $#intersection + 1;
            # if count of rules in intesection  equal to expected rules and equal count of failed rules 
            if  ($#intersection == $#$eval_match and $#intersection == $#$failed_id_rules_ref){
                record_info(
                    "Passed check of failed rules",
                    "Passed check of $fail_count expected failed rules:\n" . (join "\n",
                        @$eval_match) . "\n in file $f_stdout. \n\nMatched $failed_rules rules in file:\n" . (join "\n",
                        @$failed_id_rules_ref)
                );
                record_info(
                    "Check of failed rules",
                    "Pattern $f_fregex count in file $f_stdout is $fail_count, expected $n_failed_rules. Matched rules:\n" . (join "\n",
                        @$failed_rules_ref) . "\n\nExpected rules to fail:\n" . (join "\n",
                        @$eval_match) . "\n\nSame number $intersection_count rules in expected and failed results:\n" . (join "\n",
                        @intersection)
                );
            }
             else {
               record_info(
                    "Failed check of failed rules",
                    "#Pattern $f_fregex count in file $f_stdout is $fail_count, expected $n_failed_rules. Matched rules:\n" . (join "\n",
                        @$failed_rules_ref) . "\n\n#Expected $n_failed_rules rules to fail:\n" . (join "\n",
                        @$eval_match) . "\n\n#Rules failed (not in expected list):\n" . (join "\n",
                        @lonly),
                    result => 'fail'
                );
                 $self->result('fail');
            }
 
            #Verify number of passed and failed rules
            $pass_count = pattern_count_in_file(1, $data, $f_pregex, $passed_rules_ref, $passed_cce_rules_ref);
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
=comment #Disabled failed results analysis - done on first check
            $fail_count = pattern_count_in_file(1, $data, $f_fregex, $failed_rules_ref, $failed_cce_rules_ref);
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
=cut

=comment #Disabled bash expected results analysis
            if ($ansible_remediation == 0){
                # Compare lits of rules: list of rules not having remediation to list of rules failed evaluation
                my $miss_rem_rules_ref; # List of rules missing remediation
                my $rem_rules_ref; # List of rules having remediation
                # Get bash script name
                my $bash_script_name = profile_id_to_bash_script(1, $profile_ID);
                record_info("Got bash script name", "bash script name: $bash_script_name");
                # Get lists of of rules from the bash script returened to $miss_rem_rules_ref, $rem_rules_ref
                get_bash_expected_results (1, $bash_miss_rem_pattern, $bash_rem_pattern, $bash_script_name, $miss_rem_rules_ref, $rem_rules_ref);
                # Convert list to correct format
                my @strings;
                my @rules;
                for my $i (0 .. $#$failed_rules_ref) {
                    @strings = split /\.|\,/, $$failed_rules_ref[$i];
                    push(@rules, $strings[2]);
                }
                $lc = List::Compare->new('-u', \@$miss_rem_rules_ref, \@rules);
                # my @intersection = $lc->get_intersection;
                # Get list of failed rules which do not have remediation 
                @Ronly = $lc->get_Ronly;
                record_info(
                    "List of rules which do not have remediation",
                    "List of rules which do not have remediation: \n" . join "\n",
                    @$miss_rem_rules_ref
                );
               record_info(
                    "List of failed rules which do not have remediation",
                    "List of failed rules which do not have remediation: \n" . join "\n",
                    @Ronly
                );
            }
            else {
                # Print differnce between exluded and failed ansible rules
                my $a_exclusions = $ansible_exclusions;
                $a_exclusions =~ s/\"//g; # remove " from cce_id
                my @excluded_cce = split /\,/, $a_exclusions; # Split to array CCE IDs
                
                $lc = List::Compare->new('-u',  \@excluded_cce, \@$failed_cce_rules_ref);
                # Get list of failed rules which do not have remediation 
                @Ronly = $lc->get_Ronly;
                record_info(
                    "List excluded ansible rules",
                    "List excluded ansible rules:\n" . join "\n",
                    @excluded_cce
                );
                record_info(
                    "List of failed ansible rules except excluded",
                    "List of failed ansible rules except excluded: \n" . join "\n",
                    @Ronly
                );
            }
=cut
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
