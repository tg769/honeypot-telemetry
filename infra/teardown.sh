#!/usr/bin/env bash
# Tears down every resource provisioning created. Run when the collection
# window is over -- this is what stops the meter.
set -euo pipefail

REGION="us-east-1"
TAG="secu-honeypot"

echo "==> Finding tagged resources"
INSTANCE_ID=$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=${TAG}" "Name=instance-state-name,Values=running,stopped" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
  --filters "Name=tag:Name,Values=${TAG}" --query 'Vpcs[0].VpcId' --output text)
SUBNET_ID=$(aws ec2 describe-subnets --region "$REGION" \
  --filters "Name=tag:Name,Values=${TAG}" --query 'Subnets[0].SubnetId' --output text)
IGW_ID=$(aws ec2 describe-internet-gateways --region "$REGION" \
  --filters "Name=tag:Name,Values=${TAG}" --query 'InternetGateways[0].InternetGatewayId' --output text)
RTB_ID=$(aws ec2 describe-route-tables --region "$REGION" \
  --filters "Name=tag:Name,Values=${TAG}" --query 'RouteTables[0].RouteTableId' --output text)
SG_ID=$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=group-name,Values=${TAG}-sg" --query 'SecurityGroups[0].GroupId' --output text)

if [ "$INSTANCE_ID" != "None" ]; then
  echo "==> Terminating instance $INSTANCE_ID"
  aws ec2 terminate-instances --region "$REGION" --instance-ids "$INSTANCE_ID"
  aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$INSTANCE_ID"
fi

[ "$SG_ID" != "None" ] && aws ec2 delete-security-group --region "$REGION" --group-id "$SG_ID"
[ "$IGW_ID" != "None" ] && aws ec2 detach-internet-gateway --region "$REGION" --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID" \
  && aws ec2 delete-internet-gateway --region "$REGION" --internet-gateway-id "$IGW_ID"
[ "$SUBNET_ID" != "None" ] && aws ec2 delete-subnet --region "$REGION" --subnet-id "$SUBNET_ID"
[ "$RTB_ID" != "None" ] && aws ec2 delete-route-table --region "$REGION" --route-table-id "$RTB_ID"
[ "$VPC_ID" != "None" ] && aws ec2 delete-vpc --region "$REGION" --vpc-id "$VPC_ID"

echo "==> Done. Verify no lingering charges:"
echo "  aws ec2 describe-instances --region $REGION --filters Name=tag:Name,Values=${TAG}"
