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
    my $xccdf_eval_out = script_output "oscap xccdf eval --profile standard --results $xccdf_result $xccdf_file || true";
    uload_log_file($xccdf_result);
    record_info("xccdf_eval_out ", "$xccdf_eval_out ");
    my @xccdf_eval_regex_list = (
        qr/Rule.*xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd.*\n.*notapplicable/s,
        qr/Rule.*xccdf_org.ssgproject.content_rule_file_owner_etc_passwd.*\n.*notapplicable/s,
        qr/Rule.*xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd.*\n.*notapplicable/s
    );
    validate_file_content_regex ($xccdf_eval_out, \@xccdf_eval_regex_list, "oscap xccdf eval");

    validate_file_content($xccdf_result);
    record_info("xccdf_result_out ", "$xccdf_result_out ");
    my @xccdf_result_regex_list = (
        qr/encoding="UTF-8".*/s,
        qr/<Benchmark.*id="xccdf_org.ssgproject.content_benchmark_OPENSUSE"/s,
        qr/idref="xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd"\s+selected="true".*/s,
        qr/idref="xccdf_org.ssgproject.content_rule_file_owner_etc_passwd"\s+selected="true".*/s,
        qr/<Rule\s+id="xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd"\s+selected="false".*/s,
        qr/<Rule\s+id="xccdf_org.ssgproject.content_rule_file_owner_etc_passwd"\s+selected="false".*/s,
        qr/<TestResult id="xccdf_org.open-scap_testresult_xccdf_org.ssgproject.content_profile_standard".*cpe.*openscap.*/s,
        qr/<rule-result.*idref="xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd".*\n.*<result.*notapplicable.*/s,
        qr/<rule-result.*idref="xccdf_org.ssgproject.content_rule_file_owner_etc_passwd".*\n.*<result.*notapplicable.*/s,
        qr/<score\s+system="urn:xccdf:scoring:default".*/s,
        qr/maximum="[0-9]+/s
    );
    validate_file_content_regex ($xccdf_result_out, \@xccdf_result_regex_list, $xccdf_result);

1;
