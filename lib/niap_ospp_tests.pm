# SUSE's openQA tests
#
# Copyright 2023 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: Base module for NIAP OSPP test cases
# Maintainer: QE Security <none@suse.de>

package niap_ospp_tests;

use strict;
use warnings;
use testapi;
use utils;
use base 'opensusebasetest';
use version_utils qw(is_sle);
use bootloader_setup qw(add_grub_cmdline_settings);
use power_action_utils 'power_action';
use Utils::Backends 'is_pvm';

our @EXPORT = qw(
  $f_stdout
  $f_stderr
  $f_report

);

# The file names of logs and reports
our $f_stdout = 'stdout';
our $f_stderr = 'stderr';
our $f_vlevel = 'ERROR';

# Upload HTML report by default
set_var('UPLOAD_REPORT_HTML', 1);

sub upload_logs_reports {

    # Upload logs & ouputs for reference
    my $files;
    if (is_sle) {
        $files = script_output('ls | grep "^ssg-sle.*.xml"');
    }
    else {
        $files = script_output('ls | grep "^ssg-opensuse.*.xml"');
    }
    foreach my $file (split("\n", $files)) {
        upload_logs("$file");
    }
    upload_logs("$f_stdout") if script_run "! [[ -e $f_stdout ]]";
    upload_logs("$f_stderr") if script_run "! [[ -e $f_stderr ]]";
    if (get_var('UPLOAD_REPORT_HTML')) {
        upload_logs("$f_report", timeout => 600)
          if script_run "! [[ -e $f_report ]]";
    }
}

## remove leading and trailing whitespace from a string
sub strip {
    my $string = shift;
    $string =~ s/^\s+|\s+$//g;
    return $string;
}


1;
