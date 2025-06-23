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

    validate_script_output "oscap oval eval --results $oval_result oval.xml", sub {
        qr{
        Definition\ oval:rule_misc_sysrq:def:[0-9]:\ false.*
        Definition\ oval:no_direct_root_logins:def:[0-9]:\ false.*
        Evaluation\ done
        }sx;
    };

    validate_file_content($oval_result);
    validate_script_output "cat $oval_result", sub {
        qr{
            encoding="UTF-8".*
            <oval_results\ xmlns:xsi.*XMLSchema-instance.*
            xmlns:oval=.*oval-common-5.*xmlns=.*oval-results-5.*
            xsi:schemaLocation=.*oval-results-5.*
            oval-results-schema.xsd.*oval-common-schema.xsd">.*
            <generator>.*product_name>cpe:\/a:open-scap:oscap.*
            product_version>.*
            <oval_definitions.*
            <definition.*id="oval:rule_misc_sysrq:def:1".*compliance.*
            <criterion.*test_ref="oval:rule_misc_sysrq:tst:1".*
            <definition.*id="oval:no_direct_root_logins:def:1".*compliance.*
            <criterion.*test_ref="oval:no_direct_root_logins:tst:1".*
                        test_ref="oval:etc_securetty_exists:tst:2".*
            <results.*<system.*<definitions.*
            definition_id="oval:rule_misc_sysrq:def:1".*
            result="false".*
            definition_id="oval:no_direct_root_logins:def:1".*
            result="false"
        }sx
    }, timeout => 300;

    #$scanning_match_single
    validate_script_output "oscap oval eval --id oval:rule_misc_sysrq:def:1 --results $oval_result_single oval.xml", sub {
        qr{
        Definition\ oval:rule_misc_sysrq:def:[0-9]:\ false.*
        Evaluation\ done
        }sx
    };

    validate_file_content($oval_result_single);
    validate_script_output "cat $oval_result_single", sub {
        qr{
            encoding="UTF-8".*
            <results.*<system.*<definitions.*
            definition_id="oval:rule_misc_sysrq:def:1".*
            result="false".*
            definition_id="oval:no_direct_root_logins:def:1".*
            result="not\ evaluated"
        }sx
    }, timeout => 300;
}

1;
