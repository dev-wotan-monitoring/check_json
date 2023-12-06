#!/usr/bin/env perl
# GH-Informatik 2022-2023, based on https://github.com/c-kr/check_json

# Core modules for HTTP requests, JSON processing, and Nagios plugin support
use warnings;
use strict;
use HTTP::Request::Common;
use LWP::UserAgent;
use JSON;
use Monitoring::Plugin;
use Monitoring::Plugin::Functions qw(%STATUS_TEXT);
use Data::Dumper;

# Create a new Monitoring::Plugin object. This object will handle command line arguments
# and perform the Nagios plugin checks.
my $np = Monitoring::Plugin->new(
    usage => "Usage: %s -u|--url <http://user:pass\@host:port/url> -a|--attributes <attributes> "
        . "[ -c|--critical <thresholds> ] [ -w|--warning <thresholds> ] "
        . "[ -e|--expect <value> ] "
        . "[ -W|--warningstr <value> ] "
        . "[ -p|--perfvars <fields> ] "
        . "[ -o|--outputvars <fields> ] "
        . "[ -H|--headers <fields> ] "
        . "[ -b|--body <string> ] "
        . "[ -t|--timeout <timeout> ] "
        . "[ -d|--divisor <divisor> ] "
        . "[ -m|--metadata <content> ] "
        . "[ -T|--contenttype <content-type> ] "
        . "[ -r|--request <request-type> ] "
        . "[ -l|--labels <labels> ] "
        . "[ -L|--labelstoperf <labels> ] "
        . "[ -S|--select1 <labels> ] "
        . "[ -U|--unselect1 <labels> ] "
        . "[ --ignoressl ] "
        . "[ -h|--help ] ",
    version => '1.0',  # Version of the plugin
    blurb   => 'Nagios plugin to check JSON attributes via http(s)',  # Short description
    extra   => "\nExample: \n"
        . "check_json.pl --url http://192.168.5.10:9332/local_stats --attributes '{shares}->{dead}' "
        . "--warning :5 --critical :10 --perfvars '{shares}->{dead},{shares}->{live}' "
        . "--outputvars '{status_message}'",
    url     => 'https://github.com/c-kr/check_json',
    plugin  => 'check_json',
    timeout => 15,
    shortname => "Check JSON status API",
);

# Define the command line arguments that this plugin will accept.
# These definitions include a specification of the argument, a help description,
# and whether the argument is required or not.

# The URL to fetch the JSON from
$np->add_arg(
    spec => 'url|u=s',
    help => '-u, --url http://user:pass@192.168.5.10:9332/local_stats',
    required => 1,
);

# Attributes within the JSON to check
$np->add_arg(
    spec => 'attributes|a=s',
    help => '-a, --attributes <CSV list of perl structure IDs e.g. [0]->{state},[0]->{shares}->[0]->{uptime}',
    required => 1,
);

# Divisor for attribute values
$np->add_arg(
    spec => 'divisor|d=i',
    help => '-d, --divisor 1000000',
);

# Warning threshold for attribute values
$np->add_arg(
    spec => 'warning|w=s',
    help => '-w, --warning INTEGER:INTEGER . See '
        . 'http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT '
        . 'for the threshold format. ',
);

# Critical threshold for attribute values
$np->add_arg(
    spec => 'critical|c=s',
    help => '-c, --critical INTEGER:INTEGER . See '
        . 'http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT '
        . 'for the threshold format. ',
);

# The expected value for an attribute
$np->add_arg(
    spec => 'expect|e=s',
    help => '-e, --expect expected value to see for attribute.',
);

# The expected value for an attribute when in a warning state
$np->add_arg(
    spec => 'warningstr|W=s',
    help => '-W, --warningstr expected value to see for attribute on warning status.',
);

# The HTTP request method to use
$np->add_arg(
    spec => 'request|r=s',
    help => '-r, --request string of the desired request type. Supports get & post.',
);

# Performance data variables to pass to Nagios
$np->add_arg(
    spec => 'perfvars|p=s',
    help => "-p, --perfvars eg. '* or {shares}->{dead},{shares}->{live}'\n   "
        . "CSV list of fields from JSON response to include in perfdata "
);

# Variables to include in the output
$np->add_arg(
    spec => 'outputvars|o=s',
    help => "-o, --outputvars eg. '* or {status_message}'\n   "
        . "CSV list of fields output in status message, same syntax as perfvars"
);

# Custom headers for the HTTP request
$np->add_arg(
    spec => 'headers|H=s',
    help => "-H, --headers eg. '* or {status_message}'\n   "
        . "CSV list of custom headers to include in the json. Syntax: key1:value1#key2:value2..."
);

# Body of the HTTP request if POST is used
$np->add_arg(
    spec => 'body|b=s',
    help => "-b, --body eg. '* or {status_message}'\n   "
        . "string of the body to include."
);

# Metadata for RESTful requests in JSON format
$np->add_arg(
    spec => 'metadata|m=s',
    help => "-m|--metadata \'{\"name\":\"value\"}\'\n   "
        . "RESTful request metadata in JSON format"
);

# Content-type header value for the HTTP request
$np->add_arg(
    spec => 'contenttype|T=s',
    default => 'application/json',
    help => "-T, --contenttype application/json \n   "
        . "Content-type accepted if different from application/json ",
);

# Flag to ignore SSL certificate validation
$np->add_arg(
    spec => 'ignoressl',
    help => "--ignoressl\n   Ignore bad ssl certificates",
);

# Labels for attributes to enhance readability of the output
$np->add_arg(
    spec => 'labels|l=s',
    help => "--labels\n   Put the same number as attributes in the same syntax as attributes to display  ",
);

# Whether to add labels to performance data
$np->add_arg(
    spec => 'labelstoperf|L=s',
    help => "-L, --labelstoperf\n   Add labels to perfvars 0 or 1  ",
);

# Filter labels using regular expressions
$np->add_arg(
    spec => 'select1|S=s',
    help => "-S, --select1\n   Filter labels via reg.expr. ",
);

# Exclude labels using regular expressions
$np->add_arg(
    spec => 'unselect1|U=s',
    help => "-U, --unselect1\n   Remove labels via reg.expr. ",
);

# Process the command line arguments and set up the Monitoring::Plugin object
$np->getopts;

# If verbose mode is on, print the plugin object for debugging
if ($np->opts->verbose) { (print Dumper ($np))};

# The rest of the code proceeds to perform the HTTP request, parse the JSON response,
# check the thresholds for the specified attributes, generate performance data,
# and output the results in the format expected by Nagios.

# The actual checking of the JSON attributes is done in a complex loop that
# evaluates Perl expressions to traverse the JSON structure, extract the values,
# and compare them against the thresholds.

# This includes handling special cases like wildcard attributes, resolving them
# against the actual structure of the JSON response, and applying filters using
# regular expressions.

# Lastly, the program defines a subroutine 'json_node' that extracts a value from
# the JSON response given a Perl expression that represents the path to the value.
# It uses 'eval' to safely execute the dynamic code generated based on the path expression.

# Please note that 'eval' can be dangerous if not used carefully, as it can execute
# arbitrary Perl code. In this script, it's controlled and used to navigate the JSON structure.

# The exit status of the script will be determined by the most severe result
# obtained from checking all attributes.


## GET URL
my $ua = LWP::UserAgent->new;

$ua->env_proxy;
$ua->agent('check_json/0.5');
$ua->default_header('Accept' => 'application/json');
$ua->protocols_allowed( [ 'http', 'https'] );
$ua->parse_head(0);
$ua->timeout($np->opts->timeout);

if ($np->opts->ignoressl) {
    $ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);
}

if ($np->opts->verbose) { (print Dumper ($ua))};

my $response;

#Add custom header values. example below
#my %headers = ('x-Key' => 'x-Value');
#$headers{'xkeyx'} = 'xtokenx';
my %headers;
if ($np->opts->headers) {
    foreach my $key (split('#', $np->opts->headers)) {
        my @header = split(':', $key);
        $headers{$header[0]} = $header[1];
    }
}

if ($np->opts->request eq 'post') {
    my $json = '';
    if ($np->opts->body) {
        $json = $np->opts->body;
    }

    my $req = HTTP::Request->new( 'POST', $np->opts->url);
    $req->header( %headers );
    $req->content( $json );
    $response = $ua->request( $req );

}else {
    if ($np->opts->metadata) {
        $response = $ua->request(GET $np->opts->url, 'Content-type' => 'application/json', 'Content' => $np->opts->metadata, %headers);
    } else {
        $response = $ua->request(GET $np->opts->url, %headers);
    }
}

if ($response->is_success) {
    if (!($response->header("content-type") =~ $np->opts->contenttype)) {
        $np->nagios_exit(UNKNOWN,"Content type is not JSON: ".$response->header("content-type"));
    }
} else {
    $np->nagios_exit(CRITICAL, "Connection failed: ".$response->status_line);
}


# The following section deals with the parsing of the JSON response.

# Parse JSON response from the HTTP request
# decode_json function converts the JSON string into a Perl data structure
my $json_response = decode_json($response->content);
if ($np->opts->verbose) { (print Dumper ($json_response))};

# Split attributes and labels into arrays for processing
my @attributes = split(',', $np->opts->attributes);
my @labels = split(',', $np->opts->labels);
my @select1 = (exists($np->{opts}->{select1}) and (defined $np->{opts}->{select1}) and ($np->{opts}->{select1} ne '')) ? split(',', $np->{opts}->{select1}): () ;
my @unselect1 = (exists($np->{opts}->{unselect1}) and (defined $np->{opts}->{unselect1}) and ($np->{opts}->{unselect1} ne '')) ? split(',', $np->{opts}->{unselect1}) : ();
my @warning = split(',', $np->opts->warning);
my @critical = split(',', $np->opts->critical);
my $default_warning = exists($warning[0]) ? $warning[0] : undef;
my $default_critical = exists($critical[0]) ? $critical[0] : undef;
my @statusmsg;
my @divisor = $np->opts->divisor ? split(',',$np->opts->divisor) : () ;
my $result = -1;
my $resultTmp;

# Checks if attributes, labels, select and unselect arrays have the same length
# This is required for matching each attribute with its corresponding label and selection criteria
# If they don't match, exit with an UNKNOWN status as this is a user configuration error
if (scalar @labels > 0 && scalar @labels != scalar @attributes){
    $np->nagios_exit(UNKNOWN, "--labels and --attributes have to have the same length");
}
if (scalar @select1 > 0 && scalar @select1 != scalar @attributes){
    $np->nagios_exit(UNKNOWN, "--select1 and --attributes have to have the same length");
}
if (scalar @unselect1 > 0 && scalar @unselect1 != scalar @attributes){
    $np->nagios_exit(UNKNOWN, "--unselect1 and --attributes have to have the same length");
}

# Check for wildcard characters in attributes and resolve them
# Wildcards allow for checking multiple items in an array within the JSON without specifying indices

#Resolve [*] in attributes
if ($np->opts->attributes =~ '\[\*\]') {
    if ($np->opts->verbose) {print " Found wildcard in attributes!\n"};
    # Process each attribute that has a wildcard character

    while (my ($attr_i, $attribute_str) = each @attributes) {
        # Resolve wildcard character by iterating over elements in the JSON response that match the pattern
        # This is done using the json_node subroutine which is explained further below
        # It effectively expands one attribute with wildcard into multiple attributes for each item in the array
 
        my $label_str = exists($labels[$attr_i]) ? $labels[$attr_i] : undef ;
        my $select1_str = exists($select1[$attr_i]) ? $select1[$attr_i] : undef ;
        my $unselect1_str = exists($unselect1[$attr_i]) ? $unselect1[$attr_i] : undef ;

        if ($attribute_str =~ '\[\*\]') {

            if ($label_str && $label_str !~ '\[\*\]') {
                $np->nagios_exit(UNKNOWN, "You have to use wildcards for labeling " . $attribute_str);
            }
            my $wildcard_pos = index($attribute_str, "[*]");
            if ($label_str && $wildcard_pos != index($label_str, "[*]")) {
                $np->nagios_exit(UNKNOWN, "Wildcard position for labeling must be the same as for attributes in " . $attribute_str);
            }

            if ($wildcard_pos > 0) {
                $wildcard_pos = $wildcard_pos - 2;
            }
            my $attr_sub = substr($attribute_str, 0, $wildcard_pos);
            my $label_sub = (defined $label_str) ? substr($label_str, 0, $wildcard_pos) : undef;
            if ($np->opts->verbose) {print "strpos of [*] in $attr_sub is $wildcard_pos\n"};

            my @json_node_array = @{json_node($attr_sub, $json_response)};
            my @json_label_node_array;
			
            if (($label_str) and (defined $label_sub) ) {				
                @json_label_node_array = @{json_node($label_sub, $json_response)};
            }
            if ($np->opts->verbose) {print "Resolve array of length " . scalar @json_node_array . "\n"};
            splice(@attributes, $attr_i, 1);
            if (@json_label_node_array) {
                splice(@labels, $attr_i, 1);
                splice(@select1, $attr_i, 1) if (defined $select1_str);
                splice(@unselect1, $attr_i, 1) if (defined $unselect1_str);
            }
            my $count = 0;

            while (my ($array_index, $array_item) = each @json_node_array) {
                #print Dumper(@attributes) . "\n";
                #my $elem_edit = $attribute_str =~ s/\[\*\]/$attr_sub\[$count\]/r;
                my $elem_edit = $attribute_str =~ s/\[\*\]/\[$count\]/r;
                my $check_value = json_node($elem_edit, $json_response);
                if (defined($check_value) ){
                    splice(@attributes, $count + $attr_i, 0, "$elem_edit");
					if ($np->opts->verbose) {print "Add attribute " . ( $count + $attr_i ) . " : " . $elem_edit . "\n"};
                    if (@json_label_node_array) {
                        #my $label_path = $label_str =~ s/\[\*\]/$label_sub\[$count\]/r;
                        my $label_path = $label_str =~ s/\[\*\]/\[$count\]/r;
                        splice(@labels, $count + $attr_i, 0, $label_path);
                        splice(@select1, $count + $attr_i, 0, $select1_str) if (defined $select1_str);
                        splice(@unselect1, $count + $attr_i, 0, $unselect1_str) if (defined $unselect1_str);
                    }
                    #print Dumper($attributes[$count]) . "\n";
                }
                $count++;
            }
        }
    }
}
# After resolving any wildcards, we now have a list of actual attributes to check
# This hash associates each attribute with its metadata like label, warning/critical thresholds

my %attributes = map { $attributes[$_] => { label => $labels[$_], warning => ($warning[$_] or $default_warning), critical => ($critical[$_] or $default_critical), divisor => ($divisor[$_] or 0), status => "OK" } } 0..$#attributes;
my @longmsg;

# The main checking loop
# For each attribute, we extract its value from the JSON response and compare it against the thresholds
# If the check fails, we update the result with the most severe status encountered

while (my ($attr_i, $attribute) = each @attributes) {
    my $check_value;
	my $filter1_value='';
    my $select1_str = exists($select1[$attr_i]) ? $select1[$attr_i] : undef ;
    my $unselect1_str = exists($unselect1[$attr_i]) ? $unselect1[$attr_i] : undef ;

	if(exists($labels[$attr_i])){
 		$filter1_value = json_node($labels[$attr_i], $json_response);
 		$filter1_value='' if (!defined $filter1_value);
 		if (defined $select1_str) {
 			if (! ( ($filter1_value eq '' and $select1_str eq '') or ($select1_str ne '' and $filter1_value =~ m/$select1_str/ ) ) ) {
 				$attributes{$attribute}=undef;
 				next;
 			}
 		}
 		if (defined $unselect1_str) {
 			if ( ( ($filter1_value eq '' and $unselect1_str eq '') or ($unselect1_str ne '' and $filter1_value =~ m/$unselect1_str/ ) ) ) {
 				$attributes{$attribute}=undef;
 				next;
 			}
 		}
	}
    
    if ($np->opts->verbose) {print "Check attribute " . $attr_i . "\n"};

    # Extract the value from the JSON response for the current attribute		
    $check_value = json_node($attribute, $json_response);
    # If the value is undefined, exit with UNKNOWN status
    
    if (!defined $check_value) {
        $np->nagios_exit(UNKNOWN, "No value received");
    }
    $resultTmp = 0;

    my $cmpv1 = ".*";
    $cmpv1 = $np->opts->expect if (defined( $np->opts->expect ) );
    my $cmpv2;
    $cmpv2 = $np->opts->warningstr if (defined( $np->opts->warningstr ) );

    if ( $cmpv1 eq '.*' ) {
        if ($attributes{$attribute}{'divisor'}) {
            $check_value = $check_value/$attributes{$attribute}{'divisor'};
        }
    }

    # GHI GH-Informatik, changed fixed string compare to regex
    # if (defined $np->opts->expect && $np->opts->expect ne $check_value) {

    if (defined($cmpv1 ) && ( ! ( $check_value =~ m/$cmpv1/ ) ) && ( ! ($cmpv1 eq '.*') ) ) {
        if (defined($cmpv2 ) && ( ! ($cmpv2 eq '.*') ) && ( $check_value =~ m/$cmpv2/ ) ) {
            $resultTmp = 1;
            if(!exists($labels[$attr_i])){
                $labels[$attr_i] = "Matched expected WARNING string(" . $cmpv2 . ")";
            }
            # $np->nagios_exit(WARNING, "Expected WARNING value (" . $cmpv2 . ") found. Actual: " . $check_value);
        }else{
            $resultTmp = 2;
            if(!exists($labels[$attr_i])){
                if(defined($cmpv2)) {
                    $labels[$attr_i] = "Neither matching OK (" . $cmpv1 . ") nor (" . $cmpv2 . ")";
                }else{
                    $labels[$attr_i] = " No match(" . $cmpv1 . ")";
                }
            }
            # $np->nagios_exit(CRITICAL, "Expected OK and WARNING value (" . $cmpv1 . " and " . $cmpv2 . ") not found. Actual: " . $check_value);
        }

    }
    # GHI GH-Informatik, no numeric check if regex <> .*
    if ( $cmpv1 eq '.*' ) {

        if ( $check_value eq "true" or $check_value eq "false" ) {
            if ( $check_value eq "true") {
            	$check_value = 1;
                $resultTmp = 0;
                if ($attributes{$attribute}{'critical'} eq 1 or $attributes{$attribute}{'critical'} eq "true") {
                    $resultTmp = 2;
                }
                else
                {
                    if ($attributes{$attribute}{'warning'} eq 1 or $attributes{$attribute}{'warning'} eq "true") {
                        $resultTmp = 1;
                    }
                }
            } else {
            	$check_value = 0;
                $resultTmp = 0;
                if ($attributes{$attribute}{'critical'} eq 0 or $attributes{$attribute}{'critical'} eq "false") {
                    $resultTmp = 2;
                }
                else
                {
                    if ($attributes{$attribute}{'warning'} eq 0 or $attributes{$attribute}{'warning'} eq "false") {
                        $resultTmp = 1;
                    }
                }
            }

        }
        else
        {
            $resultTmp = $np->check_threshold(
                check => $check_value,
                warning => $attributes{$attribute}{'warning'},
                critical => $attributes{$attribute}{'critical'}
            );
        }
		if ($np->opts->labelstoperf eq 1){
			if (exists($labels[$attr_i])) {
		        my $label = json_node($labels[$attr_i], $json_response);
		        if ($label) {
		            $label =~ s/[^a-zA-Z0-9_-]//g  ;
		            $np->add_perfdata(
		                label => lc $label,
		                value => $check_value,,
		                  threshold => $np->set_thresholds( warning => $attributes{$attribute}{'warning'}, critical => $attributes{$attribute}{'critical'}),
		            ) if ($label);
		        }
			}
		}     
    }
    $result = $resultTmp if $result < $resultTmp;

    $attributes{$attribute}{'check_value'}=$check_value;
    if (exists($labels[$attr_i])) {
        my $label_node = json_node($labels[$attr_i], $json_response);
        my $label = $label_node ? $label_node : $labels[$attr_i];
        push(@longmsg, "[".$STATUS_TEXT{$resultTmp}."] ".$label.": ".$check_value."\n");
    }
}


# routine to add perfdata from JSON response based on a loop of keys given in perfvals (csv)


if ($np->opts->perfvars) {
    foreach my $key ($np->opts->perfvars eq '*' ? map { "{$_}"} sort keys %$json_response : split(',', $np->opts->perfvars)) {
        # use last element of key as label
        my $label = (split('->', $key))[-1];
        # make label ascii compatible
        $label =~ s/[^a-zA-Z0-9_-]//g  ;
        my $perf_value;
        $perf_value = $json_response->{$label};
        if ($np->opts->verbose) { print Dumper ("JSON key: ".$label.", JSON val: " . $perf_value) };
        if ( defined($perf_value) ) {
            # add threshold if attribute option matches key
            if ($attributes{$key}) {
                push(@statusmsg, "$label: $attributes{$key}{'check_value'}");
                $np->add_perfdata(
                    label => lc $label,
                    value => $attributes{$key}{'check_value'},
                    threshold => $np->set_thresholds( warning => $attributes{$key}{'warning'}, critical => $attributes{$key}{'critical'}),
                );
            } else {
                push(@statusmsg, "$label: $perf_value");
                $np->add_perfdata(
                    label => lc $label,
                    value => $perf_value,
                );
            }
        }
    }
}

# output some vars in message
if ($np->opts->outputvars) {
    foreach my $key ($np->opts->outputvars eq '*' ? map { "{$_}"} sort keys %$json_response : split(',', $np->opts->outputvars)) {
        # use last element of key as label
        my $label = (split('->', $key))[-1];
        # make label ascii compatible
        $label =~ s/[^a-zA-Z0-9_-]//g;
        my $output_value;
        $output_value = $json_response->{$label};
        push(@statusmsg, "$label: $output_value");
    }
}
my $outputstr = join(', ', @statusmsg);
if(scalar @longmsg > 0) {
    $outputstr = "\n\n".join('', @longmsg);
}

$np->nagios_exit(
    return_code => $result,
    message     => $outputstr,
);

# The subroutine json_node is used to navigate the JSON structure and extract the value of a specified attribute.
# It does this by evaluating a string that represents a Perl expression to access the desired value in the JSON response.
sub json_node{
    my $json_node;
    my ($attribute, $json_response) = @_ ;
    # The variable $json_node will hold the value extracted from the JSON response
    my $json_node_str;
    # If the attribute path is empty, return the entire JSON response
    if(length $attribute ==0){
        $json_node = $json_response;
    }else{
        # Construct a Perl expression to access the desired value in the JSON structure
        $json_node_str = '$json_node = $json_response->'.$attribute;
        # print "Run Eval: $json_node_str\n";
        # Evaluate the expression safely using eval
        # If the attribute path is incorrect, eval will catch any errors without crashing the program

        eval $json_node_str;
        my $v_json_node = $json_node;
        $v_json_node = '' if (! defined $json_node);
         # If verbose mode is on, print the extracted value for debugging
        if ($np->opts->verbose) { print "Extracted $attribute: $json_node_str : ". $v_json_node ."\n" };
    }

    # Return the extracted value
    return $json_node;
}
