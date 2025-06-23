# Copyright 2018 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Test SCAP source data stream
# Maintainer: QE Security <none@suse.de>
# Tags: poo#36910, tc#1621172

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use openscaptest;

sub run {

    my $xccdf_12 = 'xccdf-1.2.xml';

    my $openscap_p = script_output "rpm -qa | grep -P \"openscap-\\d\"";
    my $openscap_v = (split(/-/, $openscap_p))[1];
    my $v_target = "1.3.6";    # After openscap-1.3.6 sds-compose tool is EOL

    # Convert to XCCDF version 1.2 and validate
    assert_script_run "xsltproc --stringparam reverse_DNS com.suse /usr/share/openscap/xsl/xccdf_1.1_to_1.2.xsl xccdf.xml > $xccdf_12";
    assert_script_run "oscap xccdf validate $xccdf_12";

    # Generate source datastream
    if ($openscap_v gt $v_target) {
        record_info("Using python script", "openscap version $openscap_v is GREATER than $v_target, sds-compose tool is EOL- using python script");
        assert_script_run "python3 $py_sds_compose_script -x $xccdf_12 -o oval.xml --out $source_ds";
    }
    else {
        record_info("Using ds sds-compose method", "openscap version $openscap_v is equal or lower to $v_target, still using ds sds-compose method");
        assert_script_run "oscap ds sds-compose $xccdf_12 $source_ds";
    }

    validate_file_content($source_ds);
    validate_script_output "cat $source_ds", sub {
        qr/
            <ds:data-stream-collection.*
            <ds:component\s+id=.*xml.*
            <ns\d+:definition.*class.*compliance.*oval:no_direct_root_logins:def:1
            <ns\d+:reference\s+ref_id.*no_direct_root_logins.*
            <ds:component\s+id=.*xml.*
            Benchmark.*xccdf_com.suse_benchmark_test.*
            Profile.*xccdf_com.suse_profile_standard.*
            Rule.*xccdf_com.suse_rule_no_direct_root_logins.*selected.*false.*
            Rule.*xccdf_com.suse_rule_rule_misc_sysrq.*selected.*false/sx
    }, timeout => 300;

    # Scanning with source datastream
    assert_script_run "oscap xccdf eval --results $source_ds_result $source_ds";
    validate_file_content($source_ds_result);
    validate_script_output "cat $source_ds_result", sub {
        qr/
            version="[0-9]+\.[0-9]+"\s+encoding="UTF-8".*
            <Profile\s+id="xccdf_com\.suse_profile_standard".*
            select.*xccdf_com\.suse_rule_no_direct_root_logins".*selected="true".*
            select.*xccdf_com\.suse_rule_rule_misc_sysrq".*selected="true".*
            Rule.*xccdf_com\.suse_rule_no_direct_root_logins".*selected="false".*
            Rule.*xccdf_com\.suse_rule_rule_misc_sysrq".*selected="false".*
            <TestResult.*<benchmark.*id="xccdf_com\.suse_benchmark_test".*
            rule-result.*xccdf_com\.suse_rule_no_direct_root_logins".*\n.*notselected.*
            rule-result.*xccdf_com\.suse_rule_rule_misc_sysrq.*\n.*notselected/sxx
    }, timeout => 300;
}

1;
