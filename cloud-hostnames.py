#!/usr/bin/env python

# This script creates DNS entries for cloud instances and stories copies
# in DynamoDB for quick and easy access.  The following environment variables
# are expected: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and DYNAMODB_TABLE

import argparse
import json
import os
from socket import gethostname
from subprocess import call
from syslog import syslog
import urllib2

from pynamodb.models import Model
from pynamodb.attributes import UnicodeAttribute


class Hostnames(Model):
    """ This class models the DynamoDB table schema. """
    class Meta:
        table_name = os.environ['DYNAMODB_TABLE']
        region = 'us-east-1'
    hostname = UnicodeAttribute(hash_key=True)


def metadata(uri):
    """ Fetches data from the EC2 meta-data API.

    Keyword arguments:
    uri -- the API endpoint to query
    """
    API = 'http://169.254.169.254/latest/meta-data'
    try:
        return urllib2.urlopen(url='%s/%s' % (API, uri)).read()
    except urllib2.HTTPError, e:
        if e.code == 404:
            return False
        else:
            raise


def get_hostnames():
    """ Gets the instance's hostnames.  Returns a tuple of:
        (vpc_id, public_hostname, private_hostname)
    If vpc_id or public_hostname are not valid, those values will be False.
    """
    mac = metadata('network/interfaces/macs/').strip('/')
    # 404s if not in a VPC
    vpc_id = metadata('network/interfaces/macs/{mac}/vpc-id'.format(mac=mac))
    # 404s if no public IP
    public_hostname = metadata('public-hostname')
    # Should always work
    private_hostname = metadata(
        'network/interfaces/macs/{mac}/local-hostname/'.format(mac=mac))

    return (vpc_id, public_hostname, private_hostname)


def run_cli53(ec2_hostname, public=False):
    """ Runs cli53 to create a CNAME for the local host pointing to
    EC2's managed DNS record.  Also creates a second CNAME with dashes removed
    that's easier to type on mobile devices.  Returns the primary CNAME, but
    not the one with dashes removed.

    Keyword arguments:
    ec2_hostname -- The instance's hostname provided by EC2.
    public -- Used to indicate a public hostname. If so, pass in True.
    """
    hostname = gethostname()
    # Assuming we won't use deeper sub-domains...
    host, domain, tld = hostname.split('.')
    domain = '%s.%s' % (domain, tld)

    if public:
        host = host + '-public'

    # Add a second record with no dashes that's easier to type on mobile deices
    host_no_dashes = host.replace('-', '')

    cmd = ("/usr/local/bin/cli53 rrcreate --replace {domain} "
           "'{host} 60 CNAME {ec2_hostname}.'")
    cmds = (cmd.format(domain=domain, host=host,
                       ec2_hostname=ec2_hostname),
            cmd.format(domain=domain, host=host_no_dashes,
                       ec2_hostname=ec2_hostname))
    for cmd in cmds:
        syslog('Running command %s' % cmd)
        call(cmd, shell=True)

    return '%s.%s' % (host, domain)


def register(hostnames):
    """
    If a host has a public and private address, we register <nostname>-public
    and <hostname> as independent and unique records. Most of the time if a
    host has a public and private address, we will want to use the private
    address as it's internal and more secure. Therefore, we default to the
    private address as the primary record.

    If there is no public IP, then we only register a private record for
    <hostname>.

    If the host is in EC2-Classic rather than in a VPC, then we only register
    the <hostname> address.

    Returns a dictionary of the records that were added.

    Keyword arguments:
    hostnames -- A tuple of (vpc_id, public_hostname, private_hostname)
    """
    vpc_id, public_hostname, private_hostname = hostnames
    records = []

    if vpc_id:
        if public_hostname:
            records.append(run_cli53(private_hostname))
            records.append(run_cli53(public_hostname, public=True))
        else:
            records.append(run_cli53(private_hostname))
    else:
        records.append(run_cli53(public_hostname, public=True))

    return records


def add_dynamo_hostnames(records):
    """ Inserts the provided values into DynamoDB """
    for hostname in records:
        row = Hostnames(hostname)
        row.save()
    syslog('Added %s to DynamoDB' % records)


def delete_dynamo_hostname(hostname):
    """ Deletes the given hostname from DynamoDB.

    Keyword arguments:
    hostname -- The hostname string to delete
    """
    host = Hostnames.get(hostname)
    host.delete()
    syslog('Deleted %s from DynamoDB' % hostname)


def list_dynamo_hostnames():
    """ Lists the hostnames from DynamoDB. """
    dump = json.loads(Hostnames.dumps())
    dump.sort()
    for host in dump:
        print host[0]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', action='store_true',
                        help='List the cloud hostnames from dynamodb')
    parser.add_argument('--delete',
                        help='Delete the given hostname from dynamodb')
    args = parser.parse_args()

    if args.list:
        list_dynamo_hostnames()
    elif args.delete:
        delete_dynamo_hostname(args.delete)
    else:
        hostnames = get_hostnames()
        records = register(hostnames)
        add_dynamo_hostnames(records)
