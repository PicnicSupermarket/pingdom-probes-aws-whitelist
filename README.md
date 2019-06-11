### Sync Pingdom probe IPs to AWS security groups

A script for synchronizing [AWS security
group](https://docs.aws.amazon.com/opsworks/latest/userguide/best-practices-groups.html)
ingress rules with the published list of [Pingdom probe IPv4
addresses](https://my.pingdom.com/probes/ipv4).  This script is inspired by and
an alternative to the following projects:
- [`akremer/pingdom-ec2-security`](https://github.com/akremer/pingdom-ec2-security)
- [`degiere/pingdom-ec2-security-group-updater`](https://github.com/degiere/pingdom-ec2-security-group-updater)

Advantages of this script over either or both of the scripts listed above:
- It is not affected by the AWS limit of 50 ingress rules per SG, as multiple
  security groups may (and should!) be provided.
- It does not unnecessarily modify the security groups upon repeated
  invocations.
- It drops obsolete ingress rules.

#### Usage

By default the script adds a TCP port 80 ingress rule for each Pingdom probe
IP. It modifies only listed security groups. For all supported options, run the
script with `--help`:

```
$ ./sync-pingdom-ec2-security-groups.py --help
usage: sync-pingdom-ec2-security-groups.py [-h] [--profile PROFILE]
                                           [--region REGION]
                                           [--whitelist WHITELIST]
                                           [--protocol {icmp,tcp,udp}]
                                           [--from-port FROM_PORT]
                                           [--to-port TO_PORT]
                                           [--rules-per-security-group RULES_PER_SECURITY_GROUP]
                                           security-group [security-group ...]

positional arguments:
  security-group        One of the security groups to be updated

optional arguments:
  -h, --help            show this help message and exit
  --profile PROFILE     The AWS config profile to use; defaults to the default
                        profile
  --region REGION       The AWS region where the security groups are located;
                        defaults to the environment's default region
  --whitelist WHITELIST
                        The URL at which the IP whitelist is located; must
                        contain one one IP per line
  --protocol {icmp,tcp,udp}
                        The protocol used by the Pingdom probe
  --from-port FROM_PORT
                        The lowest port on which Pingdom probes
  --to-port TO_PORT     The highest port on which Pingdom probes
  --rules-per-security-group RULES_PER_SECURITY_GROUP
                        The maximum number of rules per security group
```

Note that your environment must be configured to provide valid AWS credentials.
See the [Boto
documentation](https://boto3.readthedocs.io/en/latest/guide/configuration.html)
or the [AWS CLI
documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)
for instructions on how to set this up.

#### Example invocation

The following run shows the effect of synchronizing a set of three security
groups (with anonymized IDs) after Pingdom abandoned four IPs since the script
was last run:


```
$ ./sync-pingdom-ec2-security-groups.py sg-12345678 sg-23456789 sg-34567890
Dropping from SG sg-12345678: Permission tcp:78.31.69.179/32:80-80
Dropping from SG sg-12345678: Permission tcp:76.72.171.180/32:80-80
Dropping from SG sg-12345678: Permission tcp:158.58.173.160/32:80-80
Dropping from SG sg-12345678: Permission tcp:72.46.140.186/32:80-80
Adding to SG sg-12345678: Permission tcp:54.70.202.58/32:80-80
Adding to SG sg-12345678: Permission tcp:52.197.224.235/32:80-80
Adding to SG sg-12345678: Permission tcp:52.63.164.147/32:80-80
Adding to SG sg-12345678: Permission tcp:23.111.152.74/32:80-80
Dropping from SG sg-23456789: Permission tcp:54.70.202.58/32:80-80
Dropping from SG sg-23456789: Permission tcp:52.197.224.235/32:80-80
Dropping from SG sg-23456789: Permission tcp:52.63.164.147/32:80-80
Dropping from SG sg-23456789: Permission tcp:23.111.152.74/32:80-80
Adding to SG sg-23456789: Permission tcp:52.63.142.2/32:80-80
Adding to SG sg-23456789: Permission tcp:52.209.34.226/32:80-80
Adding to SG sg-23456789: Permission tcp:178.255.154.2/32:80-80
Adding to SG sg-23456789: Permission tcp:54.68.48.199/32:80-80
Dropping from SG sg-34567890: Permission tcp:52.63.142.2/32:80-80
Dropping from SG sg-34567890: Permission tcp:52.209.34.226/32:80-80
Dropping from SG sg-34567890: Permission tcp:178.255.154.2/32:80-80
Dropping from SG sg-34567890: Permission tcp:54.68.48.199/32:80-80
SUCCESS
```

Running the script once more does not further modify the security groups:
```
$ ./sync-pingdom-ec2-security-groups.py sg-12345678 sg-23456789 sg-34567890
SUCCESS
```

#### Contributing

Contributions are welcome! Feel free to file an
[issue](https://github.com/PicnicSupermarket/pingdom-probes-aws-whitelist/issues/new)
or open a [pull
request](https://github.com/PicnicSupermarket/pingdom-probes-aws-whitelist/compare).
