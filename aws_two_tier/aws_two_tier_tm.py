#!/usr/bin/env python3
"""
Threat Model: AWS Two-Tier Architecture with Palo Alto Networks Firewall

Generated from Terraform templates in aws_two_tier/.
Models a two-tier AWS deployment with:
- Palo Alto Networks VM-Series firewall (3 interfaces: mgmt, public, private)
- WordPress/Apache web server behind the firewall
- S3-based firewall bootstrap configuration
- Wide-open security groups (critical finding)
- Hardcoded API keys in user data scripts (critical finding)

Usage:
    uv run python aws_two_tier_tm.py --list
    uv run python aws_two_tier_tm.py --dfd | dot -Tpng -o dfd.png
    uv run python aws_two_tier_tm.py --json threats.json
"""

from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    ExternalEntity,
    Process,
    Server,
)

# ── Threat Model ──────────────────────────────────────────────────────────────

tm = TM("AWS Two-Tier Architecture with Palo Alto Firewall")
tm.description = (
    "Two-tier AWS infrastructure with a Palo Alto Networks VM-Series firewall "
    "protecting a WordPress web server. The firewall bootstraps from S3 and "
    "inspects traffic between the internet and the internal web tier. "
    "Deployed via Terraform."
)
tm.isOrdered = True
tm.assumptions = [
    "Firewall bootstrap configuration in S3 is pre-provisioned",
    "Palo Alto firewall AMI is a trusted vendor image",
    "The firewall is the sole path between internet and the web subnet",
    "No other VPCs or peering connections exist",
]

# ── Trust Boundaries ─────────────────────────────────────────────────────────

internet = Boundary("Internet")
aws_cloud = Boundary("AWS Cloud (VPC 10.0.0.0/16)")
public_subnet = Boundary("Public Subnet (10.0.0.0/24)")
public_subnet.inBoundary = aws_cloud
web_subnet = Boundary("Web Subnet (10.0.1.0/24)")
web_subnet.inBoundary = aws_cloud
aws_services = Boundary("AWS Services")

# ── Actors ────────────────────────────────────────────────────────────────────

external_user = Actor("External User")
external_user.inBoundary = internet

fw_admin = Actor("Firewall Administrator")
fw_admin.inBoundary = internet
fw_admin.isAdmin = True

deployer = Actor("Terraform Deployer")
deployer.inBoundary = internet
deployer.isAdmin = True

# ── External Entities ─────────────────────────────────────────────────────────

internet_gw = ExternalEntity("Internet Gateway")
internet_gw.inBoundary = aws_cloud

s3_bootstrap = ExternalEntity("S3 Bootstrap Bucket")
s3_bootstrap.inBoundary = aws_services

# ── Servers & Processes ──────────────────────────────────────────────────────

fw_instance = Server("PA VM-Series Firewall")
fw_instance.inBoundary = public_subnet
fw_instance.OS = "PAN-OS"
fw_instance.isHardened = False
fw_instance.hasAccessControl = True
fw_instance.implementsAuthenticationScheme = True
fw_instance.sanitizesInput = False
fw_instance.definesConnectionTimeout = False
fw_instance.protocol = "HTTPS"
fw_instance.isEncrypted = True

wp_server = Server("WordPress Web Server")
wp_server.inBoundary = web_subnet
wp_server.OS = "Ubuntu"
wp_server.isHardened = False
wp_server.hasAccessControl = False
wp_server.implementsAuthenticationScheme = False
wp_server.sanitizesInput = False
wp_server.encodesOutput = False
wp_server.definesConnectionTimeout = False
wp_server.handlesResources = False

iam_bootstrap_role = Process("IAM Bootstrap Role")
iam_bootstrap_role.inBoundary = aws_services
iam_bootstrap_role.hasAccessControl = True
iam_bootstrap_role.implementsAuthenticationScheme = True

provisioning = Process("User Data Provisioning")
provisioning.inBoundary = web_subnet
provisioning.hasAccessControl = False
provisioning.implementsAuthenticationScheme = False
provisioning.sanitizesInput = False

# ── Data Assets ──────────────────────────────────────────────────────────────

fw_api_key = Data(
    name="Firewall API Key",
    description="Hardcoded PAN-OS API key exposed in user_data and check_fw.sh",
    classification=Classification.SECRET,
    isCredentials=True,
    isPII=False,
    isStored=True,
    isSourceEncryptedAtRest=False,
    isDestEncryptedAtRest=False,
)

bootstrap_config = Data(
    name="Firewall Bootstrap Config",
    description="bootstrap.xml and init-cfg.txt from S3 bucket",
    classification=Classification.SENSITIVE,
    isCredentials=False,
    isStored=True,
    isSourceEncryptedAtRest=False,
)

ssh_key = Data(
    name="SSH Key Pair",
    description="EC2 key pair (ServerKeyName) for instance access",
    classification=Classification.SECRET,
    isCredentials=True,
    isStored=True,
)

web_traffic = Data(
    name="Web Traffic",
    description="HTTP traffic to WordPress site",
    classification=Classification.PUBLIC,
    isPII=False,
)

mgmt_traffic = Data(
    name="Management Traffic",
    description="HTTPS management traffic to firewall admin console",
    classification=Classification.SENSITIVE,
    isCredentials=True,
)

terraform_state = Data(
    name="Terraform State",
    description="Terraform state file containing infrastructure details and secrets",
    classification=Classification.SECRET,
    isCredentials=True,
    isStored=True,
)

# ── Data Flows ───────────────────────────────────────────────────────────────

user_to_igw = Dataflow(external_user, internet_gw, "Internet Traffic")
user_to_igw.protocol = "HTTP"
user_to_igw.dstPort = 80
user_to_igw.data = web_traffic
user_to_igw.isEncrypted = False

igw_to_fw = Dataflow(internet_gw, fw_instance, "Inbound to FW Public Interface")
igw_to_fw.protocol = "HTTP"
igw_to_fw.dstPort = 80
igw_to_fw.data = web_traffic
igw_to_fw.isEncrypted = False

fw_to_wp = Dataflow(fw_instance, wp_server, "Inspected Traffic to Web Server")
fw_to_wp.protocol = "HTTP"
fw_to_wp.dstPort = 80
fw_to_wp.data = web_traffic
fw_to_wp.isEncrypted = False

wp_to_fw = Dataflow(wp_server, fw_instance, "Web Response")
wp_to_fw.protocol = "HTTP"
wp_to_fw.dstPort = 80
wp_to_fw.data = web_traffic
wp_to_fw.isEncrypted = False

fw_to_igw = Dataflow(fw_instance, internet_gw, "Outbound Response")
fw_to_igw.protocol = "HTTP"
fw_to_igw.data = web_traffic
fw_to_igw.isEncrypted = False

igw_to_user = Dataflow(internet_gw, external_user, "Response to User")
igw_to_user.protocol = "HTTP"
igw_to_user.data = web_traffic
igw_to_user.isEncrypted = False

admin_to_fw = Dataflow(fw_admin, fw_instance, "HTTPS Management Console")
admin_to_fw.protocol = "HTTPS"
admin_to_fw.dstPort = 443
admin_to_fw.data = mgmt_traffic
admin_to_fw.isEncrypted = True
admin_to_fw.authenticatesDestination = False

fw_to_s3 = Dataflow(fw_instance, s3_bootstrap, "Bootstrap Config Pull")
fw_to_s3.protocol = "HTTPS"
fw_to_s3.dstPort = 443
fw_to_s3.data = bootstrap_config
fw_to_s3.isEncrypted = True
fw_to_s3.authenticatesSource = True

iam_to_s3 = Dataflow(iam_bootstrap_role, s3_bootstrap, "S3 Access via IAM")
iam_to_s3.protocol = "HTTPS"
iam_to_s3.dstPort = 443
iam_to_s3.data = bootstrap_config
iam_to_s3.isEncrypted = True
iam_to_s3.authenticatesSource = True

wp_to_fw_api = Dataflow(provisioning, fw_instance, "Poll FW Readiness (Hardcoded API Key)")
wp_to_fw_api.protocol = "HTTPS"
wp_to_fw_api.dstPort = 443
wp_to_fw_api.data = fw_api_key
wp_to_fw_api.isEncrypted = True
wp_to_fw_api.authenticatesDestination = False
wp_to_fw_api.sanitizesInput = False

deployer_to_fw = Dataflow(deployer, fw_instance, "Local Provisioner: check_fw.sh")
deployer_to_fw.protocol = "HTTPS"
deployer_to_fw.dstPort = 443
deployer_to_fw.data = fw_api_key
deployer_to_fw.isEncrypted = True
deployer_to_fw.authenticatesDestination = False

# ── Run ───────────────────────────────────────────────────────────────────────

tm.process()
