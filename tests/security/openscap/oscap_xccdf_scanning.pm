# Copyright 2018 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Perform evaluation of XCCDF (The eXtensible Configuration
#          Checklist Description Format) file
# Maintainer: QE Security <none@suse.de>
# Tags: poo#36907, tc#1621171

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use openscaptest;
use version_utils qw(is_sle is_leap);

sub run {
    # Check OS release
    script_output "cat /etc/os-release";

    # Always return failed here, so we use "||true" as workaround
    my $xccdf_eval_out = script_output "oscap xccdf eval --profile standard --results $xccdf_result xccdf.xml || true";
    my @xccdf_eval_regex_list = (
        qr/Rule.*no_direct_root_logins.*fail/s,
        qr/Rule.*rule_misc_sysrq.*fail/s
    );
    validate_file_content_regex ($xccdf_eval_out, \@xccdf_eval_regex_list, "oscap xccdf eval");

    validate_file_content($xccdf_result);
    my $xccdf_result_out = script_output "cat $xccdf_result";
    my @xccdf_result_regex_list = (
        qr/encoding="UTF-8".*/s,
        qr/<Benchmark.*<Profile\s+id="standard".*<select.*/s,
        qr/idref="no_direct_root_logins"\s+selected="true".*/s,
        qr/idref="rule_misc_sysrq"\s+selected="true".*/s,
        qr/<Rule\s+id="no_direct_root_logins"\s+selected="false".*/s,
        qr/<Rule\s+id="rule_misc_sysrq"\s+selected="false".*/s,
        qr/<TestResult.*<platform.*cpe:\/o:(open)?suse.*/s,
        qr/<rule-result.*idref="no_direct_root_logins".*<result.*fail.*/s,
        qr/<rule-result.*idref="rule_misc_sysrq".*<result.*fail.*/s,
        qr/<score\s+system="urn:xccdf:scoring:default".*/s,
        qr/maximum="[0-9]+/s
    );
    validate_file_content_regex ($xccdf_result_out, \@xccdf_result_regex_list, $xccdf_result);

    # Single rule testing only available on the higher version for
    # openscap-utils
    if (!(is_sle('<15') or is_leap('<15.0'))) {    # openscap >= 1.2.16
        my $xccdf_eval_single_out = script_output "oscap xccdf eval --profile standard --rule no_direct_root_logins --results $xccdf_result_single xccdf.xml || true";
        my @xccdf_regex_list = (
            qr/Title.*Direct root Logins Not Allowed/s,
            qr/Rule.*no_direct_root_logins.*fail/s
        );
        validate_file_content_regex ($xccdf_eval_single_out, \@xccdf_regex_list, "oscap xccdf eval --profile standard --rule no_direct_root_logins");

        validate_file_content($xccdf_result_single);
        my $xccdf_result_single_out = script_output "cat $xccdf_result_single";
        my @xccdf_result_single_regex_list = (
            qr/encoding="UTF-8".*/s,
            qr/<Benchmark.*<Profile\s+id="standard".*<select.*/s,
            qr/idref="no_direct_root_logins"\s+selected="true".*/s,
            qr/idref="rule_misc_sysrq"\s+selected="true".*/s,
            qr/<Rule\s+id="no_direct_root_logins"\s+selected="false".*/s,
            qr/<Rule\s+id="rule_misc_sysrq"\s+selected="false".*/s,
            qr/<TestResult.*<platform.*cpe:\/o:(open)?suse.*/s,
            qr/<rule-result.*idref="no_direct_root_logins".*<result.*fail.*/s,
            qr/<rule-result.*idref="rule_misc_sysrq".*<result.*notselected.*/s,
            qr/<score\s+system="urn:xccdf:scoring:default".*/s,
            qr/maximum="[0-9]+/s
        );
        validate_file_content_regex ($xccdf_result_single_out, \@xccdf_result_single_regex_list, $xccdf_result_single);
    }
}

1;
