# ***************************************************************************
# Copyright (c) 2017 Google, Inc.  All rights reserved.
# ***************************************************************************
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of Google, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
#
# ******************************************************************************
# The script is used to search for expected API calls and their arguments in the
# output of drltrace. The script uses an external file which contains a list of
# strings for checking. Each string should have only constant elements that do
# not change from run to run or depend on machine architecture.
# For example:
# ~~6048~~ ADVAPI32.dll!RegQueryValueExW => ~~~~ ADVAPI32.dll!RegQueryValueExW
# arg 5: 0x001df390 => 0x400 (type=DWORD*, size=0x4) => arg 5: => 0x400 type=DWORD*

import os
import sys
import subprocess

def parse_drltrace_log(log_content, allow_api_duplicates):
    '''
    The function is used to parse drltrace output format and represents it as
    a dictionary in the following way: {API name: [list of arguments]}.

    @in log_content - drltrace output (or expected results) to parse.
    @in allow_api_duplicates - if True, the function will add unique id for
                               each duplicate and save them in a dictionary.
                               if False, the function will print error and exit
                               in case when duplicates exist.
    @out - dictionary, where a key is API call name and value is a list of its
           arguments.
    '''

    log_dict = dict()
    api_call_to_add = ""
    for i, line_to_check in enumerate(log_content):
        # search for API calls
        if line_to_check.startswith("~~") and "!" in line_to_check:
            line_to_check = line_to_check.replace("~","")
            api_call_to_add = line_to_check
            api_call_exist_name = log_dict.get(api_call_to_add, None)
            if api_call_exist_name != None:
                if allow_api_duplicates == True:
                    # append unique id (line number)
                    api_call_to_add = api_call_to_add + "_" + str(i)
                else:
                    print("Found duplicates while parsing the log file, exit.")
                    sys.exit(-1)

            log_dict[api_call_to_add] = list() # List will store arguments.
            continue
        if api_call_to_add != '':
             # It means that we are parsing arguments of API call found above.
            log_dict[api_call_to_add].append(line_to_check)
    return log_dict

def check_args(args_expected, args_log):
    '''
    The function is used to compare expected arguments with arguments printed
    by drltrace.
    @in args_expected - expected arguments.
    @in args_log - arguments printed by drltrace.
    @out - True, if arguments are the same.
           False, otherwise.
    '''

    for i, arg_expected in enumerate(args_expected):
        arg_expected = arg_expected[:-1]
        # First, take "arg x" string as a separate element.
        arg_expected = arg_expected.split(":")
        arg_id = arg_expected[0]
        arg_expected = arg_expected[1] # the rest
        arg_element = arg_expected.split(" ")
        arg_element.append(arg_id)
        for element in arg_element:
            if element == "":
                continue
            if element not in args_log[i]:
                print "Failed to find %s" % element
                # It doesn't mean that the whole test is failed, probably, we
                # pick an API call with different set arguments.
                return False
    return True

def check_log_file(log_output, expected_log_path):
    '''
    The main function for expected results checking.

    @in log_output - content of the drltrace log.
    @in expected_log_path - a path where expected log file located.
    @out -1, if the function failed to find at least one string from expected log.
          0, otherwise.
    '''
    api_calls_found_not_found = dict()
    has_errors = 0

    # read and parse expected log file and drltrace output
    expected_log_content = open(expected_log_path, 'r').readlines()
    expected_log_dict = parse_drltrace_log(expected_log_content, False)
    log_dict = parse_drltrace_log(log_output.split("\n"), True)

    print("Comparing log with expected results")
    for key_expected, args_expected in expected_log_dict.iteritems():
        key_expected = key_expected[:-1] # remove "\n"
        for key_log, args_log in log_dict.iteritems():
            if key_expected in key_log:
                # We managed to find API call, let's check its arguments.
                if check_args(args_expected, args_log) == True:
                    api_calls_found_not_found[key_expected] = 1
                    break
        if api_calls_found_not_found.get(key_expected, None) == None:
            api_calls_found_not_found[key_expected] = 0

    # print results and setup return value accordingly
    for key, value in api_calls_found_not_found.iteritems():
        if value == 1:
            print("Found %s" % key)
        else:
            print("Not found %s" % key)
            has_errors = -1
    return has_errors

def main():
    expected_log_path = sys.argv[1]
    drltrace_bin_path = sys.argv[2]
    drltrace_test_app_path = sys.argv[3]
    command = "%s -logdir - -num_max_args 15 -- %s" %\
             (drltrace_bin_path, drltrace_test_app_path)
    print("Running the following command %s" % command)
    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate() # Wait while the child process finished.
    if p.returncode != 0:
        print("drltrace finished with error %d" % p.returncode)
        sys.exit(p.returncode)
    # Drltrace prints output in STDERR when symbol '-' is specified.
    res = check_log_file(err, expected_log_path)
    sys.exit(res)
if __name__ == "__main__":
    main()
