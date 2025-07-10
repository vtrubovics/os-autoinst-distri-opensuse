# Copyright 2018 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Perform evaluation of oval (Open Vulnerability and Assessment
#          Language) file
# Maintainer: QE Security <none@suse.de>
# Tags: poo#36904, tc#1621170

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use openscaptest;

sub run {

    my $oval_eval_out = script_output "oscap oval eval --results $oval_result oval.xml";
    my @eval_regex_list = (
        qr/Definition oval:rule_misc_sysrq:def:[0-9]: false/s,
        qr/Definition oval:no_direct_root_logins:def:[0-9]: false/s,
        qr/Evaluation done/s
    );
    validate_file_content_regex ($oval_eval_out, \@eval_regex_list, "oscap oval eval");

    validate_file_content($oval_result);
    my $oval_result_out = script_output "cat $oval_result";

    my @result_regex_list = (
        qr/encoding="UTF-8".*/s,
        qr/<oval_results\s+xmlns:xsi.*XMLSchema-instance.*/s,
        qr/xmlns:oval=.*oval-common-5.*xmlns=.*oval-results-5.*/s,
        qr/xsi:schemaLocation=.*oval-results-5.*/s,
        qr/oval-results-schema.xsd.*oval-common-schema.xsd">.*/s,
        qr/<generator>.*product_name>cpe:\/a:open-scap:oscap.*/s,
        qr/product_version>.*/s,
        qr/<oval_definitions.*/s,
        qr/<definition.*id="oval:rule_misc_sysrq:def:1".*compliance.*/s,
        qr/<criterion.*test_ref="oval:rule_misc_sysrq:tst:1".*/s,
        qr/<definition.*id="oval:no_direct_root_logins:def:1".*compliance.*/s,
        qr/<criterion.*test_ref="oval:no_direct_root_logins:tst:1".*/s,
        qr/test_ref="oval:etc_securetty_exists:tst:2".*/s,
        qr/<results.*<system.*<definitions.*/s,
        qr/definition_id="oval:rule_misc_sysrq:def:1".*/s,
        qr/result="false".*/s,
        qr/definition_id="oval:no_direct_root_logins:def:1".*/s,
        qr/result="false"/s
    );
    validate_file_content_regex ($oval_result_out, \@result_regex_list, $oval_result);

    #$scanning_match_single
    my $oval_eval_id_out = script_output "oscap oval eval --id oval:rule_misc_sysrq:def:1 --results $oval_result_single oval.xml";
    my @eval_id_regex_list = (
        qr/Definition oval:rule_misc_sysrq:def:[0-9]: false/s,
        qr/Evaluation done/s
    );
    validate_file_content_regex ($oval_eval_id_out, \@eval_id_regex_list, "oscap oval eval --id oval:rule_misc_sysrq:def:1");

    validate_file_content($oval_result_single);
    my $oval_result_single_out = script_output "cat $oval_result_single";
    my @result_single_regex_list = (
        qr/encoding="UTF-8".*/s,
        qr/<results.*<system.*<definitions.*/s,
        qr/definition_id="oval:rule_misc_sysrq:def:1".*/s,
        qr/result="false".*/s,
        qr/definition_id="oval:no_direct_root_logins:def:1".*/s,
        qr/result="not evaluated"/s
    );
    validate_file_content_regex ($oval_result_single_out, \@result_single_regex_list, $oval_result_single);
}

1;
