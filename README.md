
check_json
==========

Nagios plugin to check JSON attributes via http(s).

This Plugin is a fork of the existing JSON Plugin from https://github.com/c-kr/check_json with the enhancements of using the Nagios::Plugin Perl Module, allowing to use thresholds and performance data collection from various json attributes.

Performance data is also enhanced to extract performance data compliant to Nagios and Graphite standards. One attribute is selected for thresholds check, multiple others can be added for extracting performance data. This plugin is aimed at simplifying Nagios, Icinga & Icinga2 polling of JSON status APIs.

Comparing with regular expression is supported.
Expected values for OK and WARNING status.

Custom headers and body can be added. Chose a requesttype with -r.
Example for -H: "key1:value1#key2:value2#key3:value3..."

Usage: 
```
check_json -u|--url <URL> -a|--attribute <attribute> [ -c|--critical <threshold> ] [ -w|--warning <threshold> ] [ -p|--perfvars <fields> ] [ -o|--outputvars <fields> ] [ -e|--expect <value> ] [ -W|--warningstr <value> ] [ -t|--timeout <timeout> ] [ -d|--divisor <divisor> ] [ -H|--headers <fields> ] [ -b|--body <string> ] [ -r|--request <request-type> ] [ -T|--contenttype <content-type> ] [ --ignoressl ] [ -h|--help ]
```

Example: 
```
./check_json.pl --url http://192.168.5.10:9332/local_stats --attribute '{shares}->{dead_shares}' --warning :5 --critical :10 --perfvars '{shares}->{dead_shares},{shares}->{live_shares},{clients}->{clients_connected}'
```

Result:
```
Check JSON status API OK - dead_shares: 2, live_shares: 12, clients_connected: 234 | dead_shares=2;5;10 live_shares=12 clients_connected=234
```

Requirements
============

Perl JSON package

* Debian / Ubuntu : libjson-perl libnagios-plugin-perl libwww-perl
