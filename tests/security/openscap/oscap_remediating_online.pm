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
    validate_script_output "oscap xccdf eval --remediate --profile standard --results $remediate_result xccdf.xml", sub {
        qr/
            Rule.*no_direct_root_logins.*Result.*fail.*
            Rule.*rule_misc_sysrq.*Result.*fail.*
            Starting\s+Remediation.*
            Rule.*no_direct_root_logins.*Result.*fixed.*
            Rule.*rule_misc_sysrq.*Result.*fixed/sxx
    }, timeout => 300;

    validate_file_content($remediate_result);
    if (validate_script_output "cat $remediate_result", sub {
            qr{
                version="[0-9]+\.[0-9]+"\s+encoding="UTF-8"
                <Benchmark.*<Profile\s+id="standard"
                select.*no_direct_root_logins.*selected="true"
                select.*rule_misc_sysrq.*selected="true"
                Rule.*no_direct_root_logins"\s+selected="false"
                Rule.*rule_misc_sysrq"\s+selected="false"
                TestResult.*platform.*cpe:\/o:suse
                rule-result.*no_direct_root_logins.*\s+.*result.*fixed
                rule-result.*rule_misc_sysrq.*\s+.*result.*fixed
                score\s+system="urn:xccdf:scoring:default"
                maximum="[0-9]+}sx
        }, timeout => 300)
    }
    else {
        record_soft_failure('bsc#1245559 - Open SCAP 1.3.7.+ changed remediation functionality: 2 test rules in the xccdf are not fixied - became [notapplicable]');
    }

    # Verify the remediate action result
    if (script_run "! [[ -e /etc/securetty ]]") {
        validate_script_output "cat /etc/securetty", sub { m/^$/ };
    }
    else {
        record_soft_failure('bsc#1245559 - Open SCAP 1.3.7.+ changed remediation functionality: 2 test rules in the xccdf are not fixied - became [notapplicable]');
    }
    if (validate_script_output "cat /proc/sys/kernel/sysrq", sub { m/^0$/ }) {
    }
    else {
        record_soft_failure('bsc#1245559 - Open SCAP 1.3.7.+ changed remediation functionality: 2 test rules in the xccdf are not fixied - became [notapplicable]');
    }

    # Restore
    finish_remediate_validation;
}

1;
