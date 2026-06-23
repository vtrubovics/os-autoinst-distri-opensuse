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

    my $oval_eval_out = script_output "oscap oval eval --results $oval_result $oval_file";
    my @eval_regex_list = (
        qr/Definition oval:ssg-file_groupowner_etc_passwd:def:[0-9]: false/s,
        qr/Definition oval:ssg-file_owner_etc_passwd:def:[0-9]: false/s,
        qr/Evaluation done/s
    );
    validate_file_content_regex ($oval_eval_out, \@eval_regex_list, "oscap oval eval");
    uload_log_file($oval_result);
    record_info("oval_eval_out ", "$oval_eval_out ");
    
    validate_file_content($oval_result);

    my $oval_result_out = script_output "cat $oval_result";

    my @result_regex_list = (
        qr/encoding="UTF-8".*/s,
        qr/<oval_results\s+xmlns:xsi.*XMLSchema-instance.*/s,
        qr/xmlns:oval=.*oval-common-5.*xmlns=.*oval-results-5.*/s,
        qr/xsi:schemaLocation=.*oval-results-5.*/s,
        qr/oval-results-schema.xsd.*oval-common-schema.xsd">.*/s,
        qr/<oval:product_name>cpe:\/a:open-scap:oscap.*/s,
        qr/product_version>.*/s,
        qr/<oval_definitions.*/s,
        qr/<definition.*id="oval:ssg-file_groupowner_etc_passwd:def:1".*compliance.*/s,
        qr/<definition.*id="oval:ssg-file_owner_etc_passwd:def:1".*compliance.*/s,
        qr/<results.*<system.*<definitions.*/s,
        qr/definition_id="oval:ssg-file_groupowner_etc_passwd:def:1".*/s,
        qr/result="true".*/s,
        qr/definition_id="oval:ssg-file_owner_etc_passwd:def:1".*/s,
        qr/result="true"/s
    );
    validate_file_content_regex ($oval_result_out, \@result_regex_list, $oval_result);

    #$scanning_match_single
    my $oval_eval_id_out = script_output "oscap oval eval --id oval:ssg-file_groupowner_etc_passwd:def:1 --results $oval_result_single $oval_file";
    uload_log_file($oval_result_single);
    record_info("oval_eval_id_out ", "$oval_eval_id_out ");

    my @eval_id_regex_list = (
        qr/Definition oval:ssg-file_groupowner_etc_passwd:def:[0-9]: true/s,
        qr/Evaluation done/s
    );
    validate_file_content_regex ($oval_eval_id_out, \@eval_id_regex_list, "oscap oval eval --id oval:ssg-file_groupowner_etc_passwd:def:1");

    validate_file_content($oval_result_single);
    my $oval_result_single_out = script_output "cat $oval_result_single";
    my @result_single_regex_list = (
        qr/encoding="UTF-8".*/s,
        qr/<results.*<system.*<definitions.*/s,
        qr/definition_id="oval:ssg-file_groupowner_etc_passwd:def:1".*/s,
        qr/result="true".*/s,
        qr/definition_id="oval:ssg-file_owner_etc_passwd:def:1".*/s,
        qr/result="not evaluated"/s
    );
    validate_file_content_regex ($oval_result_single_out, \@result_single_regex_list, $oval_result_single);
}

1;
