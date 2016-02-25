cloud-hostnames.py is a script for maintaining route53 CNAMES to EC2 instances.
It's intended to run when your systems boot, since that's when EC2 IPs can
change.

The script behaves differently if the instance is in a VPC or not.  As
commented in the code...

    If a host has a public and private address, we register <nostname>-public
    and <hostname> as independent and unique records. Most of the time if a
    host has a public and private address, we will want to use the private
    address as it's internal and more secure. Therefore, we default to the
    private address as the primary record.

    If there is no public IP, then we only register a private record for
    <hostname>.

    If the host is in EC2-Classic rather than in a VPC, then we only register
    the <hostname> address.

In addition to creating CNAMES in route53, we also store the hostnames in a
DynamoDB table.  The idea there is querying DynamoDB when we want to list our
hostnames is fast and easy, whereas making lots of DNS querries or API calls
is slow and might even be throttled.  This is particularly useful for
tab completion of hostnames (see the --list option and the
bash_completion.example file in this repo) and integration with monitoring
systems.

MENTION SALT REACTOR...

This script was originally written by Charles McLaughlin
<cmclaughlin@popsugar.com> for PopSugar and was largly influenced by his work
at Nextdoor.com.
