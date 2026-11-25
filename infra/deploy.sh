#!/bin/sh
# Deploy Agent Shield to AWS (ECS Fargate + EFS + ALB + CloudFront), or read its access token, or tear it down.
#
#   npm run aws:deploy               deploy or update (region: $AWS_REGION, default us-west-2)
#   npm run aws:token                print the dashboard access token
#   npm run aws:destroy              delete the stack (the EFS data is kept)
#   ALERT_EMAIL=you@example.com npm run aws:deploy    also set where alert emails go
#
# Needs: AWS credentials for the target account, Docker running (to build the image), Node.js 22.
set -eu
cd "$(dirname "$0")"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}"
export AWS_REGION="$REGION"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing $1: $2" >&2; exit 1; }; }
need aws "install the AWS CLI v2"
need node "install Node.js 22"

ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || { echo "AWS credentials are not working. Run 'aws configure' or 'aws sso login' first." >&2; exit 1; }
STACK_OUT() { aws cloudformation describe-stacks --region "$REGION" --stack-name AgentShield --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text 2>/dev/null; }

case "${1:-deploy}" in
  token)
    ARN=$(aws cloudformation describe-stack-resources --region "$REGION" --stack-name AgentShield --query "StackResources[?ResourceType=='AWS::SecretsManager::Secret' && starts_with(LogicalResourceId, 'AccessToken')].PhysicalResourceId" --output text)
    aws secretsmanager get-secret-value --region "$REGION" --secret-id "$ARN" --query SecretString --output text
    exit 0 ;;
  destroy)
    [ -f .origin-secret ] || openssl rand -hex 24 > .origin-secret
    npx cdk destroy --force -c originSecret="$(cat .origin-secret)" -c region="$REGION"
    echo "Stack deleted. The EFS file system with past alerts was kept; delete it in the EFS console if you no longer need it."
    exit 0 ;;
esac

need docker "install Docker and start it (the image is built locally)"
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1 || [ -S /var/run/docker.sock ]; then
    echo "Docker needs sudo for your user, but the deploy runs docker without it. Run once:" >&2
    echo "  sudo usermod -aG docker \$USER   (then log out and back in, or run: newgrp docker)" >&2
  else echo "Docker is installed but not running. Start it and try again." >&2; fi
  exit 1
fi

# A random header value CloudFront sends to the load balancer; anything without it gets 403.
[ -f .origin-secret ] || { openssl rand -hex 24 > .origin-secret; chmod 600 .origin-secret; }

[ -d node_modules ] || npm ci --no-audit --no-fund --loglevel=error

echo "Deploying Agent Shield to account $ACCOUNT in $REGION ..."
npx cdk bootstrap "aws://$ACCOUNT/$REGION" -c originSecret="$(cat .origin-secret)" -c region="$REGION"
npx cdk deploy --require-approval never --outputs-file outputs.json \
  -c originSecret="$(cat .origin-secret)" -c region="$REGION" \
  ${ALERT_EMAIL:+-c alertEmail="$ALERT_EMAIL"} ${TARGET_REPO:+-c targetRepo="$TARGET_REPO"}

URL=$(STACK_OUT DashboardUrl)
echo ""
echo "Agent Shield is deploying its first task (clone + install takes about 2 minutes)."
echo "  Dashboard:        $URL"
echo "  Access token:     npm run aws:token"
echo "  Airwallex webhook: $(STACK_OUT AirwallexWebhookUrl)"
echo "  Integrations:     set values in Secrets Manager secret $(STACK_OUT IntegrationsSecret), then:"
echo "                    aws ecs update-service --region $REGION --cluster $(STACK_OUT ClusterName) --service $(STACK_OUT ServiceName) --force-new-deployment"
echo "  Logs:             $(STACK_OUT LogsCommand)"
