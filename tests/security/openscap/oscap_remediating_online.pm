# Copyright 2018 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Post-scan remediation test - online
# Maintainer: QE Security <none@suse.de>
# Tags: poo#36916, tc#1621174

use base "consoletest";
use strict;
use warnings;
use testapi;
use utils;
use openscaptest;

sub run {
    my $remediate_result = "scan-xccdf-remediate-results.xml";

    prepare_remediate_validation;

    # Remediate
    my $eval_output = script_output "oscap xccdf eval --remediate --profile standard --results $remediate_result xccdf.xml";
    my @eval_regex_list = (
        qr/Rule.*no_direct_root_logins.*Result.*fail.*/s,
        qr/Rule.*rule_misc_sysrq.*Result.*fail.*/s,
        qr/Starting\s+Remediation.*/s,
        qr/Rule.*no_direct_root_logins.*Result.*fixed.*/s,
        qr/Rule.*rule_misc_sysrq.*Result.*fixed/s
    );
    my $regex_res = validate_file_content_regex ($eval_output, \@eval_regex_list, "eval_output");

    if ($regex_res == 0) {
        record_info("Remediate output eval passed", "oscap xccdf eval --remediate --profile standard --results $remediate_result xccdf.xml");
    }
    else {
        record_soft_failure('bsc#1245559 - Open SCAP 1.3.7.+ remediation check failed. Possible issues: XML structure changed or rules not fixed.');
    }

    validate_file_content($remediate_result);
    my @remediate_regex_list = (
        qr/version="[0-9]+\.[0-9]+"\s+encoding="UTF-8"/s,
        qr/<Benchmark.*?<Profile\s+id="standard"/s,
        qr/select.*?no_direct_root_logins.*?selected="true"/s,
        qr/select.*?rule_misc_sysrq.*?selected="true"/s,
        qr/Rule.*?no_direct_root_logins".*?selected="false"/s,
        qr/Rule.*?rule_misc_sysrq".*?selected="false"/s,
        qr/TestResult.*?platform.*?cpe:\/o:suse/s,
        qr/rule-result idref="no_direct_root_logins.*?result.*?fixed/s,
        qr/rule-result idref="rule_misc_sysrq.*?result.*?fixed/s,
        qr/score\s+system="urn:xccdf:scoring:default".*?maximum="[0-9]+"/s
    );
    my $remediate_output = script_output "cat $remediate_result";
    $regex_res = validate_file_content_regex ($remediate_output, \@remediate_regex_list, $remediate_result);

    if ($regex_res == 0) {
        record_info("Remediate eval passed", "scap online remediation output check passed");
    }
    else {
        record_info("Remediate eval faled", "scap online remediation output check faled", result => 'fail');
        record_soft_failure('bsc#1245559 - Open SCAP 1.3.7.+ remediation check failed. Possible issues: XML structure changed or rules not fixed.');
        # result('fail');
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
