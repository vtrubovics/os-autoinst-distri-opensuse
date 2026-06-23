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

    # Convert to XCCDF version 1.2 and validate
    assert_script_run "xsltproc --stringparam reverse_DNS com.suse /usr/share/openscap/xsl/xccdf_1.1_to_1.2.xsl $xccdf_file > $xccdf_12";
    assert_script_run "oscap xccdf validate $xccdf_12";

    validate_file_content($source_ds);
    my $source_ds_content = script_output "cat $source_ds", timeout => 300;
    my @ds_regex_list = (
        qr/<ds:data-stream-collection.*/s,
        qr/<ds:component\s+id=.*xml.*/s,
        qr/<oval-def:definition.*oval:ssg-no_direct_root_logins:def:1/s,
        qr/<oval-def:reference\s+ref_id.*no_direct_root_logins.*/s,
        qr/<ds:component\s+id=.*xml.*/s,
        qr/Benchmark.*xccdf_org.ssgproject.content_benchmark_OPENSUSE.*/s,
        qr/Profile.*xccdf_org.ssgproject.content_profile_standard.*/s,
        qr/Rule.*selected.*false.*xccdf_org.ssgproject.content_rule_no_direct_root_logins/s,
        qr/idref.*xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd.*selected.*true/s
    );
    validate_file_content_regex ($source_ds_content, \@ds_regex_list, $source_ds);

    # Scanning with source datastream
    assert_script_run "oscap xccdf eval --results $source_ds_result $source_ds";
    validate_file_content($source_ds_result);
    my $source_ds_resul_content = script_output "cat $source_ds_result", timeout => 300;
    my @ds_result_regex_list = (
        qr/version="[0-9]+\.[0-9]+"\s+encoding="UTF-8".*/s,
        qr/<Profile.*xccdf_org.ssgproject.content_profile_standard.*/s,
        qr/<Rule id=.*xccdf_org.ssgproject.content_rule_no_direct_root_logins".*selected="false".*/s,
        qr/rule-result.*xccdf_org.ssgproject.content_rule_no_direct_root_logins".*\n.*notselected.*/s,
        qr/select.*xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd".*selected="true".*/s,
        qr/Rule.*xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd".*selected="false".*/s,
        qr/rule-result.*xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd.*\n.*notselected/s,
        qr/<TestResult.*\n.*<benchmark.*id="xccdf_org.ssgproject.content_benchmark_OPENSUSE".*/s
    );
    validate_file_content_regex ($source_ds_resul_content, \@ds_result_regex_list, $source_ds_result);

}

1;
