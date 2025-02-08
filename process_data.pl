#!/usr/bin/perl
use strict;
use warnings;
use List::Util qw(sum max);
use Math::BigFloat;

# Open the custom data file
my $filename = 'custom_data.txt';
open(my $fh, '<:encoding(UTF-8)', $filename) or die "Could not open file '$filename' $!";

# Read the content of the file
my $data = do { local $/; <$fh> };
close($fh);

# Print the raw data
print "Raw Data:\n$data\n\n";

# Character Frequency Analysis
my %frequency;
foreach my $char (split //, $data) {
    $frequency{$char}++;
}

# Print character frequencies
print "Character Frequencies:\n";
foreach my $char (sort keys %frequency) {
    print "$char: $frequency{$char}\n";
}

# Total number of characters
my $total_chars = length($data);
print "\nTotal Characters: $total_chars\n";

# Unique characters
my $unique_chars = keys %frequency;
print "Unique Characters: $unique_chars\n";

# Entropy Calculation
my $entropy = 0;
foreach my $char (keys %frequency) {
    my $probability = $frequency{$char} / $total_chars;
    $entropy -= $probability * log($probability) / log(2); # Calculate entropy in bits
}
print "Entropy: $entropy bits\n";

# Additional Statistics (optional)
my $max_freq = max(values %frequency);
my ($most_frequent_char) = grep { $frequency{$_} == $max_freq } keys %frequency;
print "Most Frequent Character: '$most_frequent_char' (appears $max_freq times)\n";

# Process the data as needed
# For example, split the data into lines or analyze it
my @lines = split /\n/, $data;
foreach my $line (@lines) {
    print "Processing line: $line\n";
    # Add more processing logic here as needed
}

# Additional analysis or manipulation can be done here
