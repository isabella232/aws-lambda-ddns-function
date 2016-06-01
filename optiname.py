import boto3
import hashlib
import json
import re
import time
from datetime import datetime

print('Loading function ' + datetime.now().time().isoformat())
route53 = boto3.client('route53')
ec2 = boto3.resource('ec2')
compute = boto3.client('ec2')
dynamodb_client = boto3.client('dynamodb')
dynamodb_resource = boto3.resource('dynamodb')


def lambda_handler(event, context):

    """ Check to see whether a DynamoDB table already exists. If not, create it. This table is used to keep a record of
    instances that have been created along with their attributes. This is necessary because when you terminate an
    instance its attributes are no longer available, so they have to be fetched from the table."""
    tables = dynamodb_client.list_tables()
    if 'DDNS' in tables['TableNames']:
        print 'DynamoDB table already exists'
    else:
        create_table('DDNS')

    # Set variables
    # Get the state from the Event stream
    state = event['detail']['state']

    # Get the instance id, region, and tag collection
    instance_id = event['detail']['instance-id']
    table = dynamodb_resource.Table('DDNS')

    if state == 'running':
        # Reload the instance until we find expected tags
        tries = 5
        search_tags = ['name', 'clusterid', 'elasticbeanstalk:environment-name']
        while tries > 0:
            instance = compute.describe_instances(InstanceIds=[instance_id])
            tries -= 1
            try:
                # Search for tags matching role_tags
                tags = instance['Reservations'][0]['Instances'][0]['Tags']
                next((t["Value"] for t in tags if t["Key"].lower() in search_tags))
            except:
                # Wait and try again
                print("Waiting for tags matching {} on {}".format(search_tags, instance_id))
                time.sleep(5)
                continue
            break

        # Remove response metadata from the response
        instance.pop('ResponseMetadata')
        # Remove null values from the response.  You cannot save a dict/JSON document in DynamoDB if it contains null
        # values
        instance = remove_empty_from_dict(instance)
        instance_dump = json.dumps(instance, default=json_serial)
        instance_attributes = json.loads(instance_dump)
        table.put_item(
            Item={
                'InstanceId': instance_id,
                'InstanceAttributes': instance_attributes
            }
        )
    else:
        # Fetch item from DynamoDB
        instance = table.get_item(
            Key={
                'InstanceId': instance_id
            },
            AttributesToGet=[
                'InstanceAttributes'
                ]
        )
        instance = instance['Item']['InstanceAttributes']

    try:
        tags = instance['Reservations'][0]['Instances'][0]['Tags']
    except:
        tags = []

    # Get VPC id
    vpc_id = instance['Reservations'][0]['Instances'][0]['VpcId']
    vpc = ec2.Vpc(vpc_id)

    # Is there a DHCP option set?
    # Get DHCP option set configuration
    dhcp_configurations = []
    try:
        dhcp_options_id = vpc.dhcp_options_id
        dhcp_configurations = ec2.DhcpOptions(dhcp_options_id).dhcp_configurations
    except BaseException as e:
        print 'No DHCP option set assigned to this VPC\n', e
        exit()

    # Get instance attributes
    private_ip = instance['Reservations'][0]['Instances'][0]['PrivateIpAddress']
    host_name = get_hostname(instance)
    domain_name = filter(lambda x: x['Key'] == 'domain-name', dhcp_configurations)[0]['Values'][0]['Value']
    fqdn = '.'.join((host_name, domain_name))
    print "Host Name: {}".format(host_name)
    print "Domain Name: {}".format(domain_name)

    # Get the subnet mask of the instance
    subnet_id = instance['Reservations'][0]['Instances'][0]['SubnetId']
    subnet = ec2.Subnet(subnet_id)
    cidr_block = subnet.cidr_block
    subnet_mask = int(cidr_block.split('/')[-1])

    reversed_ip_address = reverse_list(private_ip)
    reversed_domain_prefix = get_reversed_domain_prefix(subnet_mask, private_ip)
    reversed_domain_prefix = reverse_list(reversed_domain_prefix)

    # Set the reverse lookup zone
    reversed_lookup_zone = reversed_domain_prefix + '.in-addr.arpa.'
    print 'The reverse lookup zone for this instance is:', reversed_lookup_zone

    # create A records and PTR records
    if state == 'running':
        try:
            # <host_name>.<domain_name> IN A private_ip
            change_resource_record('UPSERT', fqdn, 'A', private_ip)
            # 40.20.30.10.in-addr.arpa. IN PTR <host_name>.<domain_name>.
            change_resource_record('UPSERT', '{}.in-addr.arpa.'.format(reversed_ip_address), 'PTR', "{}.".format(fqdn))
            # i-12345678.<domain_name> IN CNAME <host_name>.<domain_name>.
            change_resource_record('UPSERT', '.'.join((instance_id, domain_name, '')), 'CNAME', "{}.".format(fqdn))
            compute.create_tags(
              Resources=[instance_id],
              Tags=[{"Key": "Name", "Value": host_name}]
            )
        except BaseException as e:
            print e
    else:
        try:
            change_resource_record('DELETE', fqdn, 'A', private_ip)
            change_resource_record('DELETE', '{}.in-addr.arpa.'.format(reversed_ip_address), 'PTR', "{}.".format(fqdn))
            change_resource_record('DELETE',  '.'.join((instance_id, domain_name, '')), 'CNAME', "{}.".format(fqdn))
        except BaseException as e:
            print e

    # Loop through the instance's tags, looking for the zone and cname tags.  If either of these tags exist, check
    # to make sure that the name is valid.  If it is and if there's a matching zone in DNS, create A and PTR records.
    for tag in tags:
        if 'aliases' in tag.get('Key', {}).lstrip().lower():
            aliases = tag.get('Value')
            for alias in aliases.split(','):
                cname = alias.lstrip().lower()
                if '.' not in cname:
                    cname += domain_name
                if is_valid_hostname(cname):
                    # create CNAME record
                    if state == 'running':
                        try:
                            change_resource_record('UPSERT', cname, 'CNAME', host_name)
                        except BaseException as e:
                            print e
                    else:
                        try:
                            change_resource_record('DELETE', cname, 'CNAME', host_name)
                        except BaseException as e:
                            print e


def get_hostname(instance):
    try:
        tags = instance['Reservations'][0]['Instances'][0]['Tags']
    except IndexError:
        tags = []
    try:
        host_name = filter(lambda tag: tag["Key"] == 'Name', tags)[0]['Value']
    except IndexError:
        # Get the role id by searching the instance tags
        role_tags = ['clusterid', 'elasticbeanstalk:environment-name']
        role_id = next((t["Value"] for t in tags if t["Key"].lower() in role_tags), 'noroledef')
        instance_id = instance['Reservations'][0]['Instances'][0]['InstanceId']
        host_name = "{}-{}-{}".format(role_id, instance_id.replace('i-', ''), human_name(instance_id))
    return host_name


def human_name(orig, fmt="{adjective}{animal}"):
    with open('animals.txt') as f:
        animals = f.readlines()
    with open('adjectives.txt') as f:
        adjectives = f.readlines()

    offset = int(hashlib.md5(orig.encode()).hexdigest(), 16)
    pick = dict()
    pick['adjective'] = adjectives[offset % len(adjectives) - 1].rstrip()
    pick['animal'] = animals[offset % len(animals) - 1].rstrip()
    return fmt.format(**pick)


def create_table(table_name):
    dynamodb_client.create_table(
        TableName=table_name,
        AttributeDefinitions=[
            {
                'AttributeName': 'InstanceId',
                'AttributeType': 'S'
            },
        ],
        KeySchema=[
            {
                'AttributeName': 'InstanceId',
                'KeyType': 'HASH'
            },
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 4,
            'WriteCapacityUnits': 4
        }
    )
    table = dynamodb_resource.Table(table_name)
    table.wait_until_exists()


def change_resource_record(action, name, type, value):
    zone = None
    print("action: {}, name: {}, type: {}, value: {}".format(action, name, type, value))
    if name[-1] != '.':
        name += '.'

    zones = route53.list_hosted_zones()['HostedZones']
    for i in xrange(0, len(name.split('.'))):
        try:
            zone = filter(lambda record: record['Name'] == '.'.join(name.split('.')[i:]), zones)[0]
        except IndexError:
            continue
        break

    changes = [{
        "Action": action,
        "ResourceRecordSet": {
            "Name": name,
            "Type": type,
            "TTL": 60,
            "ResourceRecords": [{"Value": value}]
        }
    }]
    print("change_resource_record: {}".format(changes))
    route53.change_resource_record_sets(
        HostedZoneId=zone['Id'].split('/')[2],
        ChangeBatch={
            "Comment": "Updated by Lambda Optiname",
            "Changes": changes
        }
    )

def is_valid_hostname(hostname):
    """This function checks to see whether the hostname entered into the zone and cname tags is a valid hostname."""
    if hostname is None or len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def reverse_list(list):
    """Reverses the order of the instance's IP address and helps construct the reverse lookup zone name."""
    if (re.search('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', list))\
            or (re.search('\d{1,3}.\d{1,3}.\d{1,3}\.', list))\
            or (re.search('\d{1,3}.\d{1,3}\.', list))\
            or (re.search('\d{1,3}\.', list)):
        list = str.split(str(list), '.')
        list = filter(None, list)
        list.reverse()
        reversed_list = ''
        for item in list:
            reversed_list = reversed_list + item + '.'
        return reversed_list.rstrip('.')
    else:
        print 'Not a valid ip'
        exit()


def get_reversed_domain_prefix(subnet_mask, private_ip):
    """Uses the mask to get the zone prefix for the reverse lookup zone"""
    if 32 >= subnet_mask >= 24:
        third_octet = re.search('\d{1,3}.\d{1,3}.\d{1,3}.', private_ip)
        return third_octet.group(0)
    elif 24 > subnet_mask >= 16:
        second_octet = re.search('\d{1,3}.\d{1,3}.', private_ip)
        return second_octet.group(0)
    else:
        first_octet = re.search('\d{1,3}.', private_ip)
        return first_octet.group(0)


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")


def remove_empty_from_dict(d):
    """Removes empty keys from dictionary"""
    if type(d) is dict:
        return dict((k, remove_empty_from_dict(v)) for k, v in d.iteritems() if v and remove_empty_from_dict(v))
    elif type(d) is list:
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]
    else:
        return d