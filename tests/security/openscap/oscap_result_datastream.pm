# Copyright 2018 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: Test SCAP result data stream
# Maintainer: QE Security <none@suse.de>
# Tags: poo#36913, tc#1621173

use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use openscaptest;

sub run {

    ensure_generated_file($source_ds);
    assert_script_run "oscap xccdf eval --results-arf $arf_result $source_ds";

    validate_file_content($arf_result);
    my $arf_result_out = script_output "cat $arf_result";
    my @arf_result_regex_list = (
        qr/version="[0-9]+\.[0-9]+"\s+encoding="UTF-8".*/s,
        qr/<arf:asset-report-collection.*xmlns:core/s,
        qr/<ns\d:criteria\s+operator="AND".*/s,
        qr/test_ref="oval:no_direct_root_logins:tst:1.*/s,
        qr/test_ref="oval:etc_securetty_exists:tst:2.*/s,
        qr/<ns\d:criterion.*test_ref="oval:rule_misc_sysrq:tst:1".*/s,
        qr/<arf:reports.*<arf:report.*<arf:content.*<oval_results.*/s,
        qr/<oval:product_name>cpe:\/a:open-scap:oscap.*/s,
        qr/<test\s+test_id="oval:etc_securetty_exists:tst:2".*/s,
        qr/check="all"\s+result="not evaluated".*/s,
        qr/<test\s+test_id="oval:no_direct_root_logins:tst:1".*/s,
        qr/check="all"\s+result="not evaluated".*/s,
        qr/<test\s+test_id="oval:rule_misc_sysrq:tst:1".*/s,
        qr/check="at least one"\s+result="not evaluated".*/s,
        qr/\/arf:asset-report-collection>/s
    );
    validate_file_content_regex ($arf_result_out, \@arf_result_regex_list, $arf_result);
}

1;
