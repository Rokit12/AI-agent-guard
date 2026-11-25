/**
 * Agent Shield on AWS.
 *
 *   browser ──HTTPS──▶ CloudFront ──(secret origin header)──▶ Application Load Balancer ──▶ ECS Fargate task
 *                                                                                           │  ├─ Amazon EFS: alerts, emails, logs (kept across restarts)
 *   Airwallex webhooks ─▶ /api/webhooks/airwallex (signature-checked)                       │  ├─ Secrets Manager: access token, integration keys
 *                                                                                           │  └─ CloudTrail LookupEvents: live watch of this account
 *
 * - One task at a time (the alert log is append-only and has one writer).
 * - The dashboard and API need the access token generated into Secrets Manager.
 * - The load balancer answers 403 to anything that did not come through CloudFront.
 * - The agent's repository is cloned into the task on start and pulled every 30 minutes.
 *
 * Context (cdk deploy -c key=value): originSecret (required; deploy.sh makes one),
 * region (default us-west-2), targetRepo, websiteUrl, alertEmail.
 */
import { App, Stack, StackProps, Duration, RemovalPolicy, CfnOutput, SecretValue } from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as efs from "aws-cdk-lib/aws-efs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import * as secrets from "aws-cdk-lib/aws-secretsmanager";
import { Platform } from "aws-cdk-lib/aws-ecr-assets";
import type { Construct } from "constructs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

interface Props extends StackProps { originSecret: string; targetRepo: string; websiteUrl: string; alertEmail?: string }

class AgentShieldStack extends Stack {
  constructor(scope: Construct, id: string, p: Props) {
    super(scope, id, p);

    // Public subnets only and no NAT gateway: the task needs outbound internet (GitHub, npm registry, CISA feeds) and nothing else.
    const vpc = new ec2.Vpc(this, "Vpc", { maxAzs: 2, natGateways: 0, subnetConfiguration: [{ name: "public", subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 }] });

    const fs = new efs.FileSystem(this, "Data", {
      vpc, encrypted: true, removalPolicy: RemovalPolicy.RETAIN, lifecyclePolicy: efs.LifecyclePolicy.AFTER_30_DAYS,
      performanceMode: efs.PerformanceMode.GENERAL_PURPOSE, throughputMode: efs.ThroughputMode.ELASTIC,
    });
    const ap = fs.addAccessPoint("AgentShield", { path: "/agent-shield", createAcl: { ownerUid: "1000", ownerGid: "1000", permissions: "750" }, posixUser: { uid: "1000", gid: "1000" } });

    const token = new secrets.Secret(this, "AccessToken", {
      description: "Agent Shield dashboard and API access token",
      generateSecretString: { passwordLength: 40, excludePunctuation: true },
    });
    // Optional integrations: fill these in later in Secrets Manager, then restart the service.
    const integrations = new secrets.Secret(this, "Integrations", {
      description: "Agent Shield optional integrations (leave a value empty to keep it off)",
      secretObjectValue: Object.fromEntries(["AIRWALLEX_WEBHOOK_SECRET", "SMTP_URL", "SLACK_WEBHOOK_URL", "PAGERDUTY_ROUTING_KEY"].map((k) => [k, SecretValue.unsafePlainText("")])),
    });

    const task = new ecs.FargateTaskDefinition(this, "Task", {
      cpu: 512, memoryLimitMiB: 1024,
      runtimePlatform: { cpuArchitecture: ecs.CpuArchitecture.X86_64, operatingSystemFamily: ecs.OperatingSystemFamily.LINUX },
      volumes: [{ name: "data", efsVolumeConfiguration: { fileSystemId: fs.fileSystemId, transitEncryption: "ENABLED", authorizationConfig: { accessPointId: ap.accessPointId, iam: "ENABLED" } } }],
    });
    fs.grant(task.taskRole, "elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite");
    // Read-only view of this account's management events, for the live cloud monitor.
    task.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({ actions: ["cloudtrail:LookupEvents"], resources: ["*"] }));

    const logGroup = new logs.LogGroup(this, "Logs", { retention: logs.RetentionDays.ONE_MONTH, removalPolicy: RemovalPolicy.DESTROY });
    const container = task.addContainer("shield", {
      image: ecs.ContainerImage.fromAsset(ROOT, { platform: Platform.LINUX_AMD64 }),
      logging: ecs.LogDrivers.awsLogs({ streamPrefix: "shield", logGroup }),
      environment: {
        HOST: "0.0.0.0", PORT: "4600", DATA_DIR: "/data",
        TARGET_REPO: p.targetRepo, TARGET_DIR: "/app/target",
        WEBSITE_URL: p.websiteUrl, CLOUDTRAIL_LIVE: "1",
        ...(p.alertEmail ? { ALERT_EMAIL_TO: p.alertEmail } : {}),
      },
      secrets: {
        SHIELD_TOKEN: ecs.Secret.fromSecretsManager(token),
        ...Object.fromEntries(["AIRWALLEX_WEBHOOK_SECRET", "SMTP_URL", "SLACK_WEBHOOK_URL", "PAGERDUTY_ROUTING_KEY"].map((k) => [k, ecs.Secret.fromSecretsManager(integrations, k)])),
      },
      portMappings: [{ containerPort: 4600 }],
      healthCheck: { command: ["CMD-SHELL", "node -e \"fetch('http://127.0.0.1:4600/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\""], interval: Duration.seconds(30), timeout: Duration.seconds(5), startPeriod: Duration.seconds(120), retries: 3 },
    });
    container.addMountPoints({ sourceVolume: "data", containerPath: "/data", readOnly: false });

    const cluster = new ecs.Cluster(this, "Cluster", { vpc, containerInsightsV2: ecs.ContainerInsights.DISABLED });
    const service = new ecs.FargateService(this, "Service", {
      cluster, taskDefinition: task, desiredCount: 1, assignPublicIp: true, vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      minHealthyPercent: 0, maxHealthyPercent: 100, // one writer to the alert log at a time
      circuitBreaker: { rollback: true }, healthCheckGracePeriod: Duration.minutes(4),
    });
    fs.connections.allowDefaultPortFrom(service);

    const alb = new elbv2.ApplicationLoadBalancer(this, "Alb", { vpc, internetFacing: true, idleTimeout: Duration.seconds(120), dropInvalidHeaderFields: true });
    const listener = alb.addListener("Http", { port: 80, open: true, defaultAction: elbv2.ListenerAction.fixedResponse(403, { contentType: "text/plain", messageBody: "Forbidden" }) });
    const tg = new elbv2.ApplicationTargetGroup(this, "Targets", {
      vpc, port: 4600, protocol: elbv2.ApplicationProtocol.HTTP, targets: [service], deregistrationDelay: Duration.seconds(10),
      healthCheck: { path: "/healthz", healthyHttpCodes: "200", interval: Duration.seconds(30) },
    });
    // Only requests that came through CloudFront carry this header.
    listener.addAction("FromCloudFront", { priority: 1, conditions: [elbv2.ListenerCondition.httpHeader("X-Origin-Verify", [p.originSecret])], action: elbv2.ListenerAction.forward([tg]) });

    // No caching; Authorization must be in the cache key to reach the origin, so TTLs are 0 with a 1 s ceiling.
    const noCache = new cloudfront.CachePolicy(this, "NoCacheWithAuth", {
      defaultTtl: Duration.seconds(0), minTtl: Duration.seconds(0), maxTtl: Duration.seconds(1),
      headerBehavior: cloudfront.CacheHeaderBehavior.allowList("Authorization"),
      queryStringBehavior: cloudfront.CacheQueryStringBehavior.all(), cookieBehavior: cloudfront.CacheCookieBehavior.none(),
    });
    const cdn = new cloudfront.Distribution(this, "Cdn", {
      comment: "Agent Shield",
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      defaultBehavior: {
        origin: new origins.HttpOrigin(alb.loadBalancerDnsName, { protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY, readTimeout: Duration.seconds(60), keepaliveTimeout: Duration.seconds(60), customHeaders: { "X-Origin-Verify": p.originSecret } }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachePolicy: noCache,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        responseHeadersPolicy: cloudfront.ResponseHeadersPolicy.SECURITY_HEADERS,
        compress: false, // compression would buffer the live event stream
      },
    });

    new CfnOutput(this, "DashboardUrl", { value: `https://${cdn.distributionDomainName}/` });
    new CfnOutput(this, "AirwallexWebhookUrl", { value: `https://${cdn.distributionDomainName}/api/webhooks/airwallex` });
    new CfnOutput(this, "AccessTokenCommand", { value: `aws secretsmanager get-secret-value --region ${this.region} --secret-id ${token.secretArn} --query SecretString --output text` });
    new CfnOutput(this, "IntegrationsSecret", { value: integrations.secretName });
    new CfnOutput(this, "LogsCommand", { value: `aws logs tail --region ${this.region} --follow ${logGroup.logGroupName}` });
    new CfnOutput(this, "ClusterName", { value: cluster.clusterName });
    new CfnOutput(this, "ServiceName", { value: service.serviceName });
  }
}

const app = new App();
const originSecret = app.node.tryGetContext("originSecret");
if (!originSecret || String(originSecret).length < 24) throw new Error("Pass -c originSecret=<random string of 24+ characters> (infra/deploy.sh makes one for you).");
const region = app.node.tryGetContext("region") ?? process.env.AWS_REGION ?? process.env.CDK_DEFAULT_REGION ?? "us-west-2";
new AgentShieldStack(app, "AgentShield", {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region },
  description: "Agent Shield: security monitoring for AI agents that move money",
  originSecret: String(originSecret),
  targetRepo: app.node.tryGetContext("targetRepo") ?? "https://github.com/Rokit12/airwallex.git",
  websiteUrl: app.node.tryGetContext("websiteUrl") ?? "https://d1zoxhgak5pvwd.cloudfront.net/",
  alertEmail: app.node.tryGetContext("alertEmail"),
});
