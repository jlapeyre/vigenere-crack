#!/usr/bin/perl
use Getopt::Long;
use Pod::Usage;
use warnings;
use strict;
use feature ":5.10";

# print debugging message.
sub deb { my $mssg = shift; say STDERR $mssg }

my $Verbose = 0;
sub verbose { return unless $Verbose;  my $mssg = shift; $|=1; say STDERR $mssg; $|=0 }

=head1 NAME

cipher.pl - Vigenere cipher. Encoding, decoding, cracking.

=head1 SYNOPSIS

B<cipher.pl> [B<-help>] [B<-man>] [B<-encode>] [B<-decode>] [B<-crack>] 
[B<-try_length>] [B<-key I<KEY>>] [B<-threshold I<TH>>] [B<-ratio> I<RATIO>]  
[B<-max_length> I<NUM>] [B<-verbose>] [B<-pod>] [B<-ofile> I<OFILE>] [I<IFILE> ...]

See below for more description of these switches.

=head1 DESCRIPTION

I<cipher.pl> encodes plaintext and either decodes or cracks coded text using the Vigenere cipher.
For encoding, the plaintext is supplied in a file I<IFILE>, while the key, which is a string of letters
is given on the command line with B<-key>. For decoding the encoded text is supplied in the file I<IFILE>.

The option B<-freq> prints character frequencies and exits without performing any transcoding
or cracking.

Before encoding or frequency countng, the iput text is stripped of any non-alphabetic charcters and
is converted to upper case. The cracking algorithm assumes that the coded message consists only of
characters B<A-Z>.

This program was written for educational purposes.

=head1 OPTIONS

The option names may be given as unique abbreviations. 
For example, B<-dec>, or B<-d> rather than B<-decode>.

=over
  

=item B<-help>  

short help.

=item B<-man>

long help.

=item  B<-key> I<KEY> (string) 

cipher key for encoding or decoding.

=item B<-encode>      

encode the message in each input I<IFILE> using I<KEY>.
encode is the default and does not need to be specified.

=item B<-decode>       

decode the encrypted message in each I<IFILE>.

=item  B<-ofile> I<OFILE>

send output to I<OFILE> rather than standard out (the terminal).

=item  B<-crack>

Try to find the key of the encrypted message in I<IFILE> by analyzing character
frequencies.

=item  B<-try_length> I<LEN> (positive integer)

Like B<-crack>, except only keys of length I<LEN> are analyzed.

=item B<-threshold> I<TH> (floating point number) 

The threshold score at which the code is considered
cracked. Default value is C<0.1>. The key cracking algorithm
rejects scores that are higher than I<TH>. A lower value of I<TH>
requires that the trial frequency table matches more closely
the standard frequency table.

=item B<-ratio> I<RATIO> (positive integer)

Only the first C<I<RATIO> * key_length> characters of the encrypted message are analyzed when
cracking. The default value of I<RATIO> is C<1000>. Try increasing this value if the
algorithm fails to find the key. If I<RATIO> is zero or negative, then the entire
encrypted message is analyzed.

=item B<-max_length> I<NUM> (positive integer)

The maximum keylength to try when cracking. If this option is not given, the
maximum defaults to the length of the encoded message in I<IFILE>.

=item B<-freq>

Compute and print the frequency table of the input file and exit.

=item B<-verbose>

Print some informative messages while running.

=item B<-pod>

Write this documentation to the file F<README.pod>.

=back

=head1 EXAMPLES

=over

=item *

Encode the text in F<ulysses.txt> with key C<joyce> and write the
result to F<codedtext.txt>.

     cipher.pl -key joyce  -o codedtext.txt ulysses.txt

=item *

Decode the text in F<codedtext.txt> and write the
result to F<decodedtext.txt>.

     cipher.pl -key joyce  -dec  -o decodedtext.txt codedtext.txt

=item *

Try to find the encryption key used to encode input file F<codedtext.txt>.

     cipher.pl -crack  codedtext.txt

=item *

Encode as above, but write output to standard out.

     cipher.pl -key joyce  ulysses.txt

=back

=head1 ALGORITHM

The cracking algorithm first searches for a key of length one, then of length two, etc. For each
key length it computes the frequencies of characters in the input text that would have been
encoded by the same position in the keyword. It then repeatedly rotates this freqency sequence and
records the rotation that gives the best match to the average frequencies in english language text.
It then averages scores from the best match for each position in the key and compares this to a
threshold value. If the average score is below the threshold, then these positions are reported
as a likely key and the program exits. Otherwise the keylength is incremented and the algorithm
continues.

The score is the average over the alphabet of the relative
mean squared deviation of the observed frequency from the
frequency standard. 

=head2 Possible Improvements

=over

=item * Account for the effect of  poisson statistics on the score.

=item * Add support for other languages.

=back

=head1 REQUIRES

Perl 5.10

=head1 AUTHOR

John Lapeyre <gjlapeyre@cpan.org>

=cut

my @abc = qw( a b c d e f g h i j k l m n o p
               q r s t u v w x y z );

my @ABC = map { uc } @abc;

# Table from http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
my $Freq_table_string = q {

# English Letter Frequency (based on a sample of 40,000 words)

#letter  count           letter  frequency

E 	21912 	  	E 	12.02
T 	16587 	  	T 	9.10
A 	14810 	  	A 	8.12
O 	14003 	  	O 	7.68
I 	13318 	  	I 	7.31
N 	12666 	  	N 	6.95
S 	11450 	  	S 	6.28
R 	10977 	  	R 	6.02
H 	10795 	  	H 	5.92
D 	7874 	  	D 	4.32
L 	7253 	  	L 	3.98
U 	5246 	  	U 	2.88
C 	4943 	  	C 	2.71
M 	4761 	  	M 	2.61
F 	4200 	  	F 	2.30
Y 	3853 	  	Y 	2.11
W 	3819 	  	W 	2.09
G 	3693 	  	G 	2.03
P 	3316 	  	P 	1.82
B 	2715 	  	B 	1.49
V 	2019 	  	V 	1.11
K 	1257 	  	K 	0.69
X 	315 	  	X 	0.17
Q 	205 	  	Q 	0.11
J 	188 	  	J 	0.10
Z 	128 	  	Z 	0.07

};


# $hash input hash of letter counts indexed by letters.
# returns array of frequencies from A to Z.
# in (hashref $hash)
# out arrayref or array @array
sub freq_hash_to_array {
    my ($hash) = @_;
    my @array;
    map { push @array , $hash->{$_} || 0 } @ABC;
    return wantarray ? @array : \@array;
}

# inplace convert array of counts to frequencies.
# in (arrayref $array)
# out arrayref
sub normalize_freq_array {
    my ($array) = @_;
    my $sum = 0;
    foreach (@$array) { $_ = 0 unless $_  }
    $sum += $_  foreach (@$array);
    map { $_ /= $sum  } @$array;
    $array;
}

# return array of letter frequencies from A to Z
# build this by reading the table copied from source
# referenced above.
# in ()
# out arrayref
sub get_normal_frequency_table {
    my %table_hash;
    foreach ( split /\n/ , $Freq_table_string ) {
        next if /\#/;
        my ($let1, $n, $let, $freq) = split;
        next unless $let1;
        $table_hash{$let} = $freq/100;
    }
    my @table_array = freq_hash_to_array(\%table_hash);
    \@table_array;
}

# either encode or decode a message.
# input:
#  $message - a string containing plain text or coded text.
#    It can contain any character, but it is uppercased and
#    everything but A-Z is removed.
#  $key - the key to use for encrypting or decrypting.
#  $alphabet_size - number of letters in alphabet
#  $direction -  +1 for encoding,  -1 for decoding
# in (string, string, posint, posint:1)
# out string
sub encode {
    my $message = uc shift;  # convert message to all upper case.
    my $key = uc shift;      # convert key to all upper case.
    my $alphabet_size = shift;
    my $direction  = @_ ? shift : 1;
    $message =~ s/[^A-Z]//g;     # remove all but A-Z
    my $message_length = length($message);
    my $key_length = length($key);
    my $new_message = ' ' x $message_length;
    my @rots =  map { ord($_) - 65 } split '', $key; # length of rotation for each char in key
    foreach my $i (0 .. $message_length-1) { # faster ?
        substr($new_message,$i,1) =
            chr( (ord(substr($message,$i,1)) - 65 + $direction * $rots[$i % $key_length]) % $alphabet_size  + 65);
    }
    $new_message;
}


# count frequecies of characters in $message_ref.
# assume $key_length, but we don't know the key.
# We only do counts for part of the message, $ratio * $key_length characters.
# Return a list of lists. First index is index of letter in the key.
# Second index is index of letter in alphabet from A to Z.
# in (stringref, posint, posint)
# out (ref to array of arrays of float)
sub count_freq {
    my ($message_ref, $key_length, $ratio) = @_;
    my @freq_lists;
    foreach (0 .. $key_length-1) { push @freq_lists,  [(0) x 26 ] }
    my $message_length =  length($$message_ref);
    if ($ratio and $ratio > 0) {
        my $desired_mess_length = int($ratio * $key_length);
        $message_length = $desired_mess_length if $desired_mess_length < $message_length;
    }
    verbose "Counting $message_length letters";
    foreach my $i (0 .. $message_length-1) { # indeed faster than for loop!
        my $h = $freq_lists[$i % $key_length];
        ($h->[ord(substr($$message_ref,$i,1))-65]) ++;
    }
    foreach my $key_char_num (0 .. $key_length-1) { 
        my $h = $freq_lists[$key_char_num];
        normalize_freq_array($h);
    }
    return \@freq_lists;
}

# compute sum of mean sq deviation (msd) of measured
# frequencies from expected standard frequencies of english
# text. Rotate the measured frequency list 26 times by 1
# element, computing msd each time. Return the number of
# rotation giving smallest sum and the smallest sum.
# in (ref array of ints, ref array of ints)
# out (int , float)
sub analyze_freq {
    my ($freqs_measured,$freqs_standard) = @_;
    my ($i,$j,$sum,$min_j,$min_sum);
    my $alphabet_size = @$freqs_standard;
    $min_sum = 1e20;
    my $total_sum=0;
    foreach $j (0..$alphabet_size-1) {
        $sum = 0;
        foreach $i (0..$alphabet_size-1) {
            $sum += (($freqs_measured->[($i+$j)%$alphabet_size] - $freqs_standard->[$i])/
                $freqs_standard->[$i])**2;
        }
        $total_sum += $sum;
        if ($sum < $min_sum) {
            $min_sum = $sum;
            $min_j = $j;
        }
    }
    my $avg = $total_sum /= $alphabet_size;
    return($min_j,$min_sum/$avg);
}

# Compare the frequencies measured for each character position in
# the unknown key to the standard frequencies.
# Call analyze_freq for each position. Return arrays of results
# of these analyses.
# in (ref array of array of int, ref array of int)
# out ( ref array of int, string, ref array of int)
sub analyze_all_freq {
    my ($freq_list_ref,$freqs_standard) = @_;
    my (@letter_pos,@scores);
    foreach my $position (0 .. @$freq_list_ref -1) {
        my $freqs = $freq_list_ref->[$position];
        my ($let_pos, $score) = analyze_freq($freqs,$freqs_standard);
        push @letter_pos , $let_pos;
        push @scores , $score;
    }
    return(\@letter_pos, join('', map { chr(65+$_); } @letter_pos),  \@scores);
}

# Compute the frequencies of letters A-Z in the
# input message.
# Note: Using a hash is slightly faster than using ord() 
# and incrementing array elements directly.
# in (ref string)
# out (ref array of int)
sub char_freq_string {
    my ($sref) = @_;
    my %counts;
    $$sref =~ tr/[a-z]/[A-Z]/;
    $$sref =~ s/[^A-Z]//g;     # remove all but A-Z
    $counts{substr($$sref,$_,1)}++ foreach (0..length($$sref)-1);
    my @res = freq_hash_to_array(\%counts);
    return \@res;
}

# Print the results of char_freq_string
# in (ref array float)
# out ()
sub print_char_freq_count {
    my($freqs) = @_;
    my $i = 0;
    my $sum = 0;
    $sum += $_ foreach (@$freqs);
    foreach (@$freqs) {
        printf "%s %.4g\n", chr($i++ + 65) , (100* $_/ $sum);
    }
}

# Print report on score of best match for one key length.
# in (ref hash ; key => string; scores => array float)
# out ()
sub report_score {
    my ($h) = @_;
    my $key = $h->{key};
    my $len = length($key);
    my $s = "Best match: length $len,  key: $key\nScores:";
    map { $s .= sprintf " %.4g", $_ } @{$h->{scores}};
    $s .= sprintf " avg: %.4g" , $h->{avg};
}

# in (ref string, int, int, ref array of int)
# out (ref hash; avg => float; scores => ref array of float; key => string )
sub analyze_one_key_length {
    my ($input_message_ref, $key_length, $ratio, $freqs_standard) = @_;
    my $freq_lists = count_freq($input_message_ref, $key_length, $ratio);
    my ($letter_pos, $cracked_key, $scores) =  analyze_all_freq($freq_lists,$freqs_standard);
    my $avg_score = 0;
    map { $avg_score += $_ } @$scores;
    $avg_score /= @$scores;
    return  { avg => $avg_score, scores => $scores  , key => $cracked_key } ;
}

# write the pod documentation in this file to
# README.pod
sub write_readme_dot_pod {
    open my $in_fh, '<', $0 or die "Can not open file $0 for reading";
    open my $out_fh, '>', './README.pod' or die "Can not open README.pod for writing";
    while (<$in_fh>) {
        print $out_fh $_ if (/^=/../^=cut/);
    }
}

sub run_task {
    my @Input_files;
    my $Output_file = '';
    my $encode_flag = 0;
    my $decode_flag = 0;
    my $crack_flag = 0;
    my $freq_count_flag = 0;
    my $cipher_key = '';
    my $max_key_length = undef;
    my $ratio_message_to_key_length = 1000;
    my $score_threshold = 0.1;
    my $key_length = undef;
    my $Help = 0;
    my $LongHelp = 0;

    my $result = GetOptions (
        '<>' => sub { push @Input_files , $_[0] },
        'ofile=s' => \$Output_file,
        'encode' => \$encode_flag,
        'decode' => \$decode_flag,
        'try_length=i' => \$key_length,
        'crack' => \$crack_flag,
        'freq' => \$freq_count_flag,
        'max_length=i' => \$max_key_length,
        'ratio=i' => \$ratio_message_to_key_length,
        'key=s' => \$cipher_key,
        'lenkey=i' => \$key_length,
        'threshold=s' => \$score_threshold,
        'verbose' => \$Verbose,
        'man' => \$LongHelp,
        'help' => \$Help,
        'pod' => sub { write_readme_dot_pod(); exit(0) }
        );

    pod2usage(-verbose => 2) if $LongHelp;
    pod2usage(-verbose => 1) if $Help;
    pod2usage(-verbose => 1) unless @Input_files;
    verbose('Starting task.');

    my $task_flag_sum = $crack_flag + $freq_count_flag + $encode_flag + $decode_flag;
    $encode_flag = 1 if ($task_flag_sum == 0);
    if ($task_flag_sum + $encode_flag > 1) {
        say STDERR "cipher: only one of 'encode', 'decode', 'crack', or 'freq' may be set\n";
        exit(0);
    }
    my $task = 'code';
    $task = 'onelength' if $key_length;
    $task = 'crack' if $crack_flag;
    $task = 'freq' if $freq_count_flag;

    my $direction = 1 if $encode_flag;
    $direction = -1 if $decode_flag;

    my $freqs_standard = get_normal_frequency_table();
    
    my $output_handle = *STDOUT;
    open $output_handle, '>' , $Output_file or die "Unable to open output file '$Output_file'."
        if $Output_file;
    foreach my $file (@Input_files) {
        die "Unable to open file '$file' for input" unless ( -e $file and (not -d $file) and -r $file);
        my $input_message;
#        $input_message = do { local( @ARGV, $/ ) = $file ; <> } ; # not faster or slower
        my $fh;
        open $fh, '<', $file;
        sysread $fh, $input_message, -s $fh;
        chomp($input_message);
        verbose 'Read  ' . length($input_message) . " characters from input file $file";
        for ($task) {
            when ('code') {
                die  q!No key specified with '-key'! unless $cipher_key;
                my $output_message;
                $output_message = encode($input_message, $cipher_key, scalar(@$freqs_standard), $direction);
                say $output_handle $output_message;
            }
            when ('onelength') {
               my $res = analyze_one_key_length(\$input_message, $key_length, 
                                       $ratio_message_to_key_length, $freqs_standard);
               say report_score($res);
            }
            when ('crack') {
                my $max = $max_key_length || length($input_message);
                my $res;
                foreach my $length (1..$max) {
                    $res = analyze_one_key_length(\$input_message, $length, $ratio_message_to_key_length,
                                                   $freqs_standard);
                    if ($res->{avg} <= $score_threshold) {
                        last;
                    }
                    verbose(report_score($res));
                }
                say report_score($res);
            }
            when ('freq') {
                print_char_freq_count char_freq_string \$input_message;
            }
        }
    }
    close($output_handle) if $Output_file;
}    

run_task();
1;
