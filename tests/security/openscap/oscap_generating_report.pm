# Copyright 2018 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Generate document - security guide or report - form XCCDF file
# Maintainer: QE Security <none@suse.de>
# Tags: poo#36925, tc#1621177

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use openscaptest;

sub run {
    my $xccdf_guide = "xccdf_guide.html";
    my $xccdf_report = "xccdf_report.html";
    my $xccdf_fix = "xccdf_fix.sh";
    my $oval_report = "oval_report.html";
    my $xccdf_oval_report = "xccdf_oval_report.html";

    ensure_generated_file($oval_result);
    ensure_generated_file($xccdf_result);

    # Generate XCCDF guide
    assert_script_run "oscap xccdf generate guide --profile standard --output $xccdf_guide $xccdf_result";
    validate_file_content($xccdf_guide, 'html');
    validate_script_output "cat $xccdf_guide", sub {
        qr/
            Checklist.*
            Group contains 1 group and 2 rules.*
            Restrict Root Logins.*
            Direct root Logins Not Allowed.*
            sysctl kernel.sysrq must be 0.*/sxx
    }, timeout => 300;
    # Generate XCCDF report
    assert_script_run "oscap xccdf generate report --profile standard --output $xccdf_report $xccdf_result";
    validate_file_content($xccdf_report, 'html');
    validate_script_output "cat $xccdf_report", sub {
        qr/
            with profile.*Standard System Security Profile.*
            The target system did not satisfy the conditions of 2 rules.*
            Hardening SUSE Linux Enterprise.*2x fail.*
            Restrict Root Logins.*1x fail.*
            Direct root Logins Not Allowed.*
            sysctl kernel.sysrq must be 0/sxx
    }, timeout => 300;

    # Generate OVAL report
    assert_script_run "oscap oval generate report --output $oval_report $oval_result";
    validate_file_content($oval_report, 'html');
    validate_script_output "cat $oval_report", sub {
        qr/
            OVAL Results Generator Information.*
            OVAL Definition Generator Information.*
            System Information.*
            cpe:\/a:open-scap:oscap.*
            OVAL Definition Results.*
            oval:rule_misc_sysrq:def:1.*false.*
            oval:no_direct_root_logins:def:1.*false/sxx
    }, timeout => 300;

    # Generate XCCDF report with additional information from failed OVAL tests
    assert_script_run "oscap xccdf generate report --oval-template $oval_result --output $xccdf_oval_report $xccdf_result";
    validate_file_content($xccdf_oval_report, 'html');
    validate_script_output "cat $xccdf_oval_report", sub {
        qr/
            with profile.*Standard System Security Profile.*
            Evaluation Characteristics.*
            CPE Platforms.*cpe:\/o:suse.*
            Compliance and Scoring.*
            The target system did not satisfy the conditions of 2 rules.*
            Rule results.*2 failed.*
            Severity of failed rules.*1 other.*
            Score.*
            Rule Overview.*/
    }, timeout => 300;
}

1;
