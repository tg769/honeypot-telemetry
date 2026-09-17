#!/usr/bin/env bash
# Provisions the honeypot sensor: dedicated VPC, hardened EC2 instance, budget alarm.
#
# You run this yourself (not Claude) -- it creates real, billed AWS resources
# and opens a port to the internet. Review every step before running.
#
# Prereqs: `aws configure` already run with an account that has EC2/VPC/Budgets
# permissions, and an EC2 key pair already created (aws ec2 create-key-pair).
set -euo pipefail

# ---- fill these in ----
REGION="us-east-1"
KEY_NAME="secu-sensor"                 # must already exist in this region
HOME_IP_CIDR="203.0.113.99/32"         # your real IP, for admin SSH allowlist
BUDGET_EMAIL="you@example.com"
# ------------------------

VPC_CIDR="10.90.0.0/16"
SUBNET_CIDR="10.90.1.0/24"
TAG="secu-honeypot"

echo "==> VPC"
VPC_ID=$(aws ec2 create-vpc --region "$REGION" --cidr-block "$VPC_CIDR" \
  --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${TAG}}]" \
  --query 'Vpc.VpcId' --output text)
aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_ID" --enable-dns-support
aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_ID" --enable-dns-hostnames

echo "==> Subnet + Internet Gateway"
SUBNET_ID=$(aws ec2 create-subnet --region "$REGION" --vpc-id "$VPC_ID" \
  --cidr-block "$SUBNET_CIDR" \
  --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${TAG}}]" \
  --query 'Subnet.SubnetId' --output text)
IGW_ID=$(aws ec2 create-internet-gateway \
  --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${TAG}}]" \
  --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --region "$REGION" --vpc-id "$VPC_ID" --internet-gateway-id "$IGW_ID"

RTB_ID=$(aws ec2 create-route-table --region "$REGION" --vpc-id "$VPC_ID" \
  --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${TAG}}]" \
  --query 'RouteTable.RouteTableId' --output text)
aws ec2 create-route --region "$REGION" --route-table-id "$RTB_ID" \
  --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID" > /dev/null
aws ec2 associate-route-table --region "$REGION" --route-table-id "$RTB_ID" --subnet-id "$SUBNET_ID" > /dev/null
aws ec2 modify-subnet-attribute --region "$REGION" --subnet-id "$SUBNET_ID" --map-public-ip-on-launch

echo "==> Security group (bait :22 open, admin :52222 restricted, egress default-deny)"
SG_ID=$(aws ec2 create-security-group --region "$REGION" --vpc-id "$VPC_ID" \
  --group-name "${TAG}-sg" --description "honeypot sensor" \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 52222 --cidr "$HOME_IP_CIDR"

# revoke the default allow-all egress rule, then allow only DNS + HTTPS for setup
aws ec2 revoke-security-group-egress --region "$REGION" --group-id "$SG_ID" \
  --protocol -1 --cidr 0.0.0.0/0 2>/dev/null || true
aws ec2 authorize-security-group-egress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-egress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 53 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-egress --region "$REGION" --group-id "$SG_ID" \
  --protocol udp --port 53 --cidr 0.0.0.0/0

echo "==> AMI lookup (Ubuntu 24.04 arm64)"
AMI_ID=$(aws ec2 describe-images --region "$REGION" \
  --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*" \
            "Name=state,Values=available" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text)

echo "==> Launch instance (no instance profile, IMDSv2 required, hop-limit 1)"
INSTANCE_ID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI_ID" \
  --instance-type t4g.micro \
  --key-name "$KEY_NAME" \
  --subnet-id "$SUBNET_ID" \
  --security-group-ids "$SG_ID" \
  --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=8,VolumeType=gp3}' \
  --user-data file://infra/bootstrap.sh \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${TAG}}]" \
  --query 'Instances[0].InstanceId' --output text)

echo "==> Budget alarm at \$5"
aws budgets create-budget --account-id "$(aws sts get-caller-identity --query Account --output text)" \
  --budget "{\"BudgetName\":\"${TAG}\",\"BudgetLimit\":{\"Amount\":\"5\",\"Unit\":\"USD\"},\"TimeUnit\":\"MONTHLY\",\"BudgetType\":\"COST\"}" \
  --notifications-with-subscribers "[{\"Notification\":{\"NotificationType\":\"ACTUAL\",\"ComparisonOperator\":\"GREATER_THAN\",\"Threshold\":80},\"Subscribers\":[{\"SubscriptionType\":\"EMAIL\",\"Address\":\"${BUDGET_EMAIL}\"}]}]" \
  || echo "budget alarm creation failed/exists -- check manually"

echo
echo "VPC:      $VPC_ID"
echo "Subnet:   $SUBNET_ID"
echo "SG:       $SG_ID"
echo "Instance: $INSTANCE_ID"
echo
echo "Wait ~60s, then:"
echo "  aws ec2 describe-instances --region $REGION --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text"
echo "Then verify per plan Phase 0 steps 1-4 before doing anything else."
