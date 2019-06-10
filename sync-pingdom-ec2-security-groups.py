#!/usr/bin/env python

import argparse
import boto3
import requests

class Permission(object):
    def __init__(self, protocol, cidr_ip, from_port, to_port):
        self.protocol = protocol
        self.cidr_ip = cidr_ip
        self.from_port = from_port
        self.to_port = to_port

    def as_dict(self):
        return {
            'IpProtocol': self.protocol,
            'CidrIp': self.cidr_ip,
            'FromPort': self.from_port,
            'ToPort': self.to_port
        }

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(tuple(sorted(self.__dict__.items())))

    def __repr__(self):
        return 'Permission({0.protocol!r}, {0.cidr_ip!r}, {0.from_port!r}, {0.to_port!r})'.format(self)

    def __str__(self):
        return 'Permission {0.protocol}:{0.cidr_ip}:{0.from_port}-{0.to_port}'.format(self)

class PingdomSecurityGroup(object):
    def __init__(self, sg):
        self.sg = sg

    def update_permissions(self, target_perms, max_perms):
        active_perms = self.get_permissions()

        self.drop_permissions(active_perms - target_perms)
        active_perms &= target_perms
        target_perms -= active_perms

        new_perms = set(list(target_perms)[:max_perms - len(active_perms)])
        self.add_permissions(new_perms)
        target_perms -= new_perms

    def get_permissions(self):
        # XXX: Assumes that "IpRanges" contains only CIDR entries, not SG IDs.
        return set(Permission(p['IpProtocol'], r['CidrIp'], p['FromPort'], p['ToPort']) for p in self.sg.ip_permissions for r in p['IpRanges'])

    def drop_permissions(self, permissions):
        for p in permissions:
            print('Dropping from SG {0}: {1}'.format(self.sg.id, p))
            self.sg.revoke_ingress(**p.as_dict())

    def add_permissions(self, permissions):
        for p in permissions:
            print('Adding to SG {0}: {1}'.format(self.sg.id, p))
            self.sg.authorize_ingress(**p.as_dict())

class SecurityGroupUpdater(object):
    def __init__(self, session, whitelist, protocol, from_port, to_port, rules_per_security_group, security_groups):
        self.session = session
        self.whitelist = whitelist
        self.protocol = protocol
        self.from_port = from_port
        self.to_port = to_port
        self.rules_per_security_group = rules_per_security_group
        self.security_groups = security_groups

    def run(self):
        permissions = self.get_target_permissions()
        self.configure_permissions(permissions)
        if permissions:
            print('WARNING: {0} permissions could not be configured; please specify more security groups.'.format(len(permissions)))
        else:
            print('SUCCESS')

    def get_target_permissions(self):
        return set(map(self.create_permission, self.get_ips()))

    def get_ips(self):
        r = requests.request('GET', self.whitelist, timeout=10)
        r.raise_for_status()
        return set(r.iter_lines(decode_unicode=True))

    def create_permission(self, ip):
        return Permission(self.protocol, '{0}/32'.format(ip), self.from_port, self.to_port)

    def configure_permissions(self, permissions):
        ec2 = self.session.resource('ec2')
        for sg_id in self.security_groups:
            sg = PingdomSecurityGroup(ec2.SecurityGroup(sg_id))
            sg.update_permissions(permissions, self.rules_per_security_group)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--profile',
        default=None,
        help='The AWS config profile to use; defaults to the default profile')
    parser.add_argument(
        '--region',
        default=None,
        help="The AWS region where the security groups are located; defaults to the environment's default region")
    parser.add_argument(
        '--whitelist',
        default='https://my.pingdom.com/probes/ipv4',
        help='The URL at which the IP whitelist is located; must contain one one IP per line')
    parser.add_argument(
        '--protocol',
        choices=('icmp', 'tcp', 'udp'),
        default='tcp',
        help='The protocol used by the Pingdom probe')
    parser.add_argument(
        '--from-port',
        type=int,
        default=80,
        help='The lowest port on which Pingdom probes')
    parser.add_argument(
        '--to-port',
        type=int,
        default=80,
        help='The highest port on which Pingdom probes')
    parser.add_argument(
        '--rules-per-security-group',
        type=int,
        default=60,
        help='The maximum number of rules per security group')
    parser.add_argument(
        'security-group',
        nargs='+',
        help='One of the security groups to be updated')
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region, profile_name=args.profile)

    updater = SecurityGroupUpdater(session, args.whitelist, args.protocol, args.from_port, args.to_port, args.rules_per_security_group, getattr(args, 'security-group'))
    updater.run()

if __name__ == '__main__':
    main()
