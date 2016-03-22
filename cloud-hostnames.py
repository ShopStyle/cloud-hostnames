#!/usr/bin/env python

# This script creates DNS entries for cloud instances and stories copies
# in DynamoDB for quick and easy access. The following environment variables
# are expected: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION,
# DYNAMODB_TABLE and SERVICE_CNAME_FILE

import argparse
import ast
import boto
import json
import os
import urllib2

from boto.dynamodb.condition import BEGINS_WITH
from socket import gethostname
from subprocess import check_call
from syslog import syslog
from time import time


R53_CREATE_CMD = ("cli53 rrcreate --replace {domain} '{host} 60 CNAME "
                  "{ec2_hostname}.'")
R53_DELETE_CMD = 'cli53 rrdelete {domain} {host} CNAME'


class CloudHostname(object):
    """ If a host has a public and private address, we register
    <nostname>-public and <hostname> as independent and unique DNS records.
    Most of the time if a host has a public and private address, we will want
    to use the private address as it's internal and more secure. Therefore, we
    default to the private address as the primary record.

    If there is no public IP, then we only register a private record for
    <hostname>.

    If the host is in EC2-Classic rather than in a VPC, then we only register
    the <hostname> address.

    We also store a copy of the records in DynamoDB for quick and easy access.
    """

    records = []  # tracks records added in a transaction

    def __init__(self, vpc_id, public_ec2_hostname, private_ec2_hostname,
                 dry=False):
        """ Constructor/initializer for the CloudHostname class.

        Keyword arguments:
        vpc_id -- The instance's vpc_id, pass in False if we're not in a VPC.
        public_ec2_hostname -- The instance's public DNS record.
        private_ec2_hostname -- The instnace's private DNS record.
        dry -- If True we don't create route53 records, but we do log them to
               DynamoDB.
        """
        rrcreate = self.__rrcreate

        if vpc_id:
            if public_ec2_hostname:
                rrcreate(private_ec2_hostname, public_in_vpc=False, dry=dry)
                rrcreate(public_ec2_hostname, public_in_vpc=True, dry=dry)
            else:
                rrcreate(private_ec2_hostname, public_in_vpc=False, dry=dry)
        else:
            rrcreate(public_ec2_hostname, public_in_vpc=False, dry=dry)

        self.__add_dynamo_hostnames()

    def __add_dynamo_hostnames(self):
        """ Inserts/updates the route53 records in DynamoDB """
        table = self.__get_dynamo_table()

        for hostname in self.records:
            data = {'timestamp': time()}
            item = table.new_item(hash_key=hostname, attrs=data)
            item.put()
        syslog('Added/updated %s in DynamoDB' % self.records)

    def __rrcreate(self, ec2_hostname, public_in_vpc=False, dry=False):
        """ Runs cli53 to create a CNAME for the local host pointing to
        EC2's managed DNS record. Also creates a second CNAME with dashes
        removed that's easier to type on mobile devices.

        Appends the primary CNAME to the records instance variable.

        Keyword arguments:
        ec2_hostname -- The instance's hostname provided by EC2.
        public_in_vpc -- Used to indicate a public hostname inside a VPC. If
                         so, pass in True.
        dry -- Dry run, don't actually create any records.
        """
        host, domain = CloudHostname.__split_hostname(gethostname())

        if public_in_vpc:
            host = host + '-public'

        cmds = [R53_CREATE_CMD.format(
            domain=domain, host=host, ec2_hostname=ec2_hostname)]

        # Add a second record with no dashes that's easier to type on mobiles
        if '-' in host:
            cmds.append(R53_CREATE_CMD.format(
                domain=domain, host=host.replace('-', ''),
                ec2_hostname=ec2_hostname))

        if not dry:
            CloudHostname.__run_commands(cmds)

        self.records.append('%s.%s' % (host, domain))

    @staticmethod
    def __get_dynamo_table():
        """ Sets up a connnection to DynamoDB and returns a pointer to the
        hostnames table. """
        conn = boto.connect_dynamodb()
        return conn.get_table(os.environ['DYNAMODB_TABLE'])

    @staticmethod
    def __split_hostname(hostname):
        """ Splits a hostname such as my.example.com into my and example.com.
        Returns a tuple of the host (i.e. my) and domain (i.e. example.com).

        Keyword arguments:
        hostname -- A string of the hostname you want to split.
        """
        # Assuming we won't use deeper sub-domains...
        host, domain, tld = hostname.split('.')
        domain = '%s.%s' % (domain, tld)
        return (host, domain)

    @staticmethod
    def __run_commands(commands):
        """ Runs the given commands as a subprocess and logs them to syslog.

        Keyword arguments:
        commands -- List of commands to run.
        """
        for command in commands:
            syslog('Running command %s' % command)
            check_call(command, shell=True)

    @staticmethod
    def delete(hostname):
        """ Deletes the given hostname from DynamoDB and route53.

        Also deletes any "host-public.domain.tld" records, but in order to look
        for those records in DynamoDB we search for records that begin with
        "host" and make sure they end with "domain.tld", so in theory if you've
        added records that don't follow our normal pattterns the delete could
        be greedy.

        Corresponding route53 records with dashes removed are also deleted.

        Keyword arguments:
        hostname -- The hostname string to delete.  Expects the primary ID,
        not the -public or a stripped string.
        """
        host, domain = CloudHostname.__split_hostname(hostname)
        commands = []

        table = CloudHostname.__get_dynamo_table()

        for row in table.scan(scan_filter={'hostname': BEGINS_WITH(host)}):
            # Scan the entire table and searching the hostname. Verify this is
            # the record we want to delete by matching the domain. This makes
            # up for lack of searching on the hash key.
            if row['hostname'].endswith(domain):
                host_to_delete = row['hostname'].replace('.%s' % domain, '')
                commands.append(R53_DELETE_CMD.format(
                    domain=domain, host=host_to_delete))
                if '-' in host_to_delete:
                    commands.append(R53_DELETE_CMD.format(
                        domain=domain,
                        host=host_to_delete.replace('-', '')))
                row.delete()
                syslog('Deleted %s from DynamoDB' % hostname)

        CloudHostname.__run_commands(commands)

    @staticmethod
    def list():
        """ Lists the hostnames from DynamoDB. """
        table = CloudHostname.__get_dynamo_table()
        for row in table.scan():
            print row['hostname']

    @staticmethod
    def service_cname(public_ec2_hostname, private_ec2_hostname):
        """ Creates the service CNAME records that may be associated with
        this instance.

        Using configuration management, such as Salt or Puppet, you can
        write a service CNAME to the SERVICE_CNAME_FILE using this format:
        <record1> <public - True or False>
        <record2> <public - True or False>

        Here's an example:
        saltmaster.mydomain.com False

        This will result in creation of a saltmaster.mydomain.com CNAME
        record that points to the EC2 instance's private managed DNS entry.
        If the second field was True, the CNAME would point to the instance's
        public managed DNS entry.

        Please note these service CNAME records are not stored in DynamoDB
        and are not purged from route53 using the purge() method.
        They're not intended to be as dynamic as the instance CNAME records
        which change often as you boot new cloud instances. Therefore,
        deleting old service CNAME records is a manual process.

        Keyword arguments:
        public_ec2_hostname -- The instance's public DNS record.
        private_ec2_hostname -- The instnace's private DNS record.
        """
        cname_file = os.environ['SERVICE_CNAME_FILE']
        if os.path.isfile(cname_file):
            with open(cname_file, 'r') as f:
                lines = f.readlines()

            for line in lines:
                cname, public = line.split(' ')

                host, domain = CloudHostname.__split_hostname(cname)

                if ast.literal_eval(public):  # converts str to bool
                    ec2_hostname = public_ec2_hostname
                else:
                    ec2_hostname = private_ec2_hostname

                CloudHostname.__run_commands([
                    R53_CREATE_CMD.format(
                        domain=domain, host=host, ec2_hostname=ec2_hostname)])

    @staticmethod
    def purge(threshold):
        """ Deletes old records from DynamoDB and Route53.

        This is a very inefficient opperation intended to be run infrequently.
        We end up scanning the entire table twice - once to look for "original"
        hostnames (wihtout -public added), then we call the delete() method
        which also scans to search and destroy.

        Keyword arguments:
        threshold -- Records older than this number of seconds will be deleted.
        """
        table = CloudHostname.__get_dynamo_table()
        for row in table.scan():
            if '-public' not in row['hostname']:
                if time() - row['timestamp'] > threshold:
                    CloudHostname.delete(row['hostname'])

    @staticmethod
    def update(vpc_id, public_ec2_hostname, private_ec2_hostname):
        """ Updates the last_updated timestamp in DynamoDB for the given
        hostname. """
        CloudHostname(vpc_id, public_ec2_hostname, private_ec2_hostname, True)


class MetaData(object):
    """ Models the EC2 host metadata as returned by the local API """

    def __init__(self):
        """ Gets the local instance's hostnames from the local EC2 metadata
        API. Sets the following instance variables:

            vpc_id, public_ec2_hostname, private_ec2_hostname

        If vpc_id or public_ec2_hostname are not valid, those values will be
        False.
        """
        mac = self.__api_wrapper('network/interfaces/macs/').strip('/')
        # 404s if not in a VPC
        self.vpc_id = self.__api_wrapper(
            'network/interfaces/macs/{mac}/vpc-id'.format(mac=mac))
        # 404s if no public IP
        self.public_ec2_hostname = self.__api_wrapper('public-hostname')
        # Should always work
        self.private_ec2_hostname = self.__api_wrapper(
            'network/interfaces/macs/{mac}/local-hostname/'.format(mac=mac))

    def __api_wrapper(self, uri):
        """ Fetches data from the EC2 meta-data API.
        Returns data provided by the API or False on 404.

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', action='store_true',
                        help='List the cloud hostnames from DynamoDB.')
    parser.add_argument('--delete',
                        help='Delete the given hostname from DynamoDB.')
    parser.add_argument('--purge',
                        help=('Delete records that have not been updated in '
                              'the provided number of seconds.'))
    parser.add_argument('--update', action='store_true',
                        help=('Log this host as active in DynamoDB by '
                              'updating the last_updated field.'))
    args = parser.parse_args()

    if args.list:
        CloudHostname.list()
    elif args.delete:
        CloudHostname.delete(args.delete)
    elif args.purge:
        CloudHostname.purge(int(args.purge))
    elif args.update:
        metadata = MetaData()
        CloudHostname.update(metadata.vpc_id, metadata.public_ec2_hostname,
                             metadata.private_ec2_hostname)
        CloudHostname.service_cname(metadata.public_ec2_hostname,
                                    metadata.private_ec2_hostname)
    else:
        metadata = MetaData()
        CloudHostname(metadata.vpc_id, metadata.public_ec2_hostname,
                      metadata.private_ec2_hostname)
        CloudHostname.service_cname(metadata.public_ec2_hostname,
                                    metadata.private_ec2_hostname)
