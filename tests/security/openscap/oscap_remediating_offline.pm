# Copyright 2018 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Post-scan remediation test - offline
# Maintainer: QE Security <none@suse.de>
# Tags: poo#36919, tc#1621175

use base "consoletest";
use strict;
use warnings;
use testapi;
use utils;
use openscaptest;

sub run {
    my $remediate_result = "scan-xccdf-remediate-results.xml";

    ensure_generated_file($xccdf_result);
    prepare_remediate_validation;

    my $offline_rem_out = validate_script_output "oscap xccdf remediate --results $remediate_result $xccdf_result", timeout => 300;
    if ($offline_rem_out =~ qr/
        Rule.*no_direct_root_logins.*Result.*fixed.*
        Rule.*rule_misc_sysrq.*Result.*fixed/sx) {
        record_info("Offline remediate passed", "scap remediation output check passed");
    }
    else {
        record_info("Remediate eval failed", "scap online remediation output check failed", result => 'fail');
        record_soft_failure('bsc#1245559 - Open SCAP 1.3.7.+ remediation check failed. Possible issues: XML structure changed or rules not fixed.');
    }

    validate_file_content($remediate_result);
    my $remediate_result_out = script_output "cat $remediate_result");
    if ($remediate_result_out =~ qr/
        <\?xml\s+version="[0-9]+\.[0-9]+"\s+encoding="UTF-8".*
        <Benchmark.*<Profile\s+id="standard".*
        select.*no_direct_root_logins.*selected="true".*
        select.*rule_misc_sysrq.*selected="true".*
        Rule.*no_direct_root_logins"\s+selected="false".*
        Rule.*rule_misc_sysrq"\s+selected="false".*
        TestResult.*
        rule-result.*idref="no_direct_root_logins".*result.*fail.*
        rule-result.*idref="rule_misc_sysrq".*result.*fail.*
        TestResult.*
        rule-result.*idref="no_direct_root_logins".*result.*fixed.*
        rule-result.*idref="rule_misc_sysrq".*result.*fixed.*
        score\s+system="urn:xccdf:scoring:default".*
        maximum="[0-9]+/sx) {
        record_info("Check Passed", "Remediation result check passed");
    }
    else {
        record_info("Check failed", "Remediation result check faled", result => 'fail');
        record_soft_failure('bsc#1245559 - Open SCAP 1.3.7.+ remediation check failed. Possible issues: XML structure changed or rules not fixed.');
    }

    # Verify the remediate action result
    if (script_run "! [[ -e /etc/securetty ]]") {
        if (validate_script_output "cat /etc/securetty", sub { m/^$/ }) {
            record_info("Check passed", "/etc/securetty exists");
        }
        else {
            record_info("Check failed", "/etc/securetty does not contain 0", result => 'fail');
            record_soft_failure('bsc#1245559 - Open SCAP 1.3.7.+ changed remediation functionality: 2 test rules in the xccdf are not fixied - became [notapplicable]');
        }
    }
    else {
        record_info("Check failed", "/etc/securetty does not exist", result => 'fail');
        record_soft_failure('bsc#1245559 - Open SCAP 1.3.7.+ changed remediation functionality: 2 test rules in the xccdf are not fixied - became [notapplicable]');
    }

    if (script_run('grep -e \'^0$\' /proc/sys/kernel/sysrq') == 0, timeout => 30) {
        record_info("sysrq eval passed", "/proc/sys/kernel/sysrq contains 0");
    }
    else {
        record_info("Check failed", "/proc/sys/kernel/sysrq do not contain 0", result => 'fail');
        record_soft_failure('bsc#1245559 - Open SCAP 1.3.7.+ changed remediation functionality: 2 test rules in the xccdf are not fixied - became [notapplicable]');
    }

    # Restore
    finish_remediate_validation;
}

1;
