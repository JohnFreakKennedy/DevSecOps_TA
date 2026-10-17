**ENGINEERING HIRING EXERCISE**

# **Platform Security Engineer / DevSecOps**

## *Technical assessment \- candidate brief*

**Recommended timebox:** 5 hours

**Submission format:** One PDF or Markdown file plus supporting code files

**Expected level:** Hands-on senior engineer

**Environment:** No live infrastructure or production access is required

| Purpose: This exercise evaluates how you identify and prioritise risk, design practical controls, improve cloud-native delivery, respond to incidents, and validate security safely. It is intentionally broader than a penetration-testing challenge. |
| :---- |

# **Ground Rules**

* Timebox your work. We value prioritisation and clear trade-offs more than exhaustive coverage.  
* State all assumptions. You may simplify the scenario where necessary, but explain the consequence.  
* You may use documentation and AI-assisted tools. Disclose material AI use and be prepared to explain every submitted decision and code change.  
* Do not include secrets, proprietary material from current or former employers, or offensive payloads that are unnecessary to explain your approach.  
* Diagrams may be created in any readable format. Production-ready visual design is not required.

# **What We Are Looking For**

* Risk-based decisions rather than a catalogue of tools.  
* Least privilege, secure defaults, traceability, and safe operational recovery.  
* Controls that engineers can adopt without bringing delivery to a ceremonial halt.  
* Clear ownership, evidence, and a way to verify that each control actually works.  
* The ability to distinguish prevention, detection, response, and compliance evidence.

# **Scenario**

You are joining a team preparing an iGaming platform for launch in Tier-1 markets. The platform handles registration, authentication, wallet and ledger operations, deposits and withdrawals, game-provider integrations, callbacks, and a privileged backoffice.

The engineering team ships frequently and wants security controls built into its normal delivery workflow. A separate external penetration test will take place before launch. Your role combines platform engineering, cloud security, secure delivery, detection engineering, incident readiness, and controlled purple-team validation.

| Area | Current state |
| :---- | :---- |
| Cloud | AWS organisation; separate dev, staging, and production accounts; eu-central-1 |
| Runtime | EKS; Node.js/NestJS microservices; container images in ECR |
| Data | RDS PostgreSQL, Redis, Kafka or RabbitMQ, object storage |
| Delivery | GitLab CI/CD and Terraform; approximately 20 deployments per week |
| Identity | Google Workspace; AWS IAM Identity Center; NetBird for private access |
| Edge | Cloudflare in front of public web and API endpoints |
| Observability | CloudTrail, EKS audit logs, application telemetry, and a central observability platform |
| Team | Two DevOps/Platform engineers, five backend engineers, two Tech Leads, and QA |

## **Constraints**

* The launch is planned in eight weeks.  
* No single control may depend on one person being permanently available.  
* Production offensive testing requires written approval, an allowlist, a defined window, a kill switch, and complete auditability.  
* Customer and financial data must not be copied into developer environments.  
* The team needs a realistic first release of the security programme, not an ideal-state three-year transformation.

# **Part 1 \- Risk and Security Architecture**

Produce a concise security design and prioritised launch plan.

1. Create a one-page architecture or trust-boundary diagram showing public entry points, EKS, data stores, CI/CD, identity, administrative access, security telemetry, and third-party integrations.  
2. Identify the eight highest launch risks. For each, include the affected asset, realistic threat, impact, proposed control, verification evidence, owner, and priority.  
3. Define the access model for engineers, DevOps, Security, Support, and break-glass administrators. Explain joiner, mover, leaver, temporary-access, and emergency-access flows.  
4. Choose the five controls you would deliver in the first 30 days and explain why they outrank the rest.

# **Part 2 \- Practical Review and Remediation**

Review the synthetic snippets below. They are intentionally incomplete and insecure. Identify the important issues, prioritise them, and provide corrected excerpts or precise implementation guidance. You do not need to produce a complete runnable repository.

## **2A. Terraform / AWS**

resource "aws\_eks\_cluster" "platform" {  
  name     \= "platform-prod"  
  role\_arn \= aws\_iam\_role.eks.arn  
   
  vpc\_config {  
    subnet\_ids              \= var.public\_subnet\_ids  
    endpoint\_public\_access  \= true  
    endpoint\_private\_access \= false  
    public\_access\_cidrs     \= \["0.0.0.0/0"\]  
  }  
}  
   
resource "aws\_iam\_policy" "ci" {  
  name \= "gitlab-ci"  
  policy \= jsonencode({  
    Version \= "2012-10-17"  
    Statement \= \[{  
      Effect   \= "Allow"  
      Action   \= "\*"  
      Resource \= "\*"  
    }\]  
  })  
}  
   
resource "aws\_db\_instance" "wallet" {  
  identifier          \= "wallet-prod"  
  engine              \= "postgres"  
  publicly\_accessible \= true  
  storage\_encrypted   \= false  
  backup\_retention\_period \= 1  
  skip\_final\_snapshot \= true  
}  
   
resource "aws\_s3\_bucket" "audit" {  
  bucket \= "platform-audit-prod"  
}

*Your response should distinguish urgent launch blockers from later hardening and include the operational consequences of your changes.*

## **2B. Kubernetes Workload**

apiVersion: apps/v1  
kind: Deployment  
metadata:  
  name: callback-handler  
spec:  
  replicas: 1  
  template:  
    spec:  
      serviceAccountName: default  
      containers:  
        \- name: app  
          image: registry.example.com/callback-handler:latest  
          securityContext:  
            privileged: true  
            runAsUser: 0  
          env:  
            \- name: DB\_PASSWORD  
              value: "production-password"  
          ports:  
            \- containerPort: 3000

## **2C. GitLab Pipeline**

stages: \[build, deploy\]  
   
build:  
  image: docker:latest  
  services: \[docker:dind\]  
  script:  
    \- docker login \-u "\$REGISTRY\_USER" \-p "\$REGISTRY\_PASSWORD" "\$CI\_REGISTRY"  
    \- docker build \-t "\$IMAGE:latest" .  
    \- docker push "\$IMAGE:latest"  
   
deploy\_prod:  
  stage: deploy  
  only: \[main\]  
  script:  
    \- aws eks update-kubeconfig \--name platform-prod  
    \- kubectl set image deployment/callback-handler app="\$IMAGE:latest"

## **Required Output for Part 2**

* A prioritised findings list with severity and rationale.  
* Corrected or replacement excerpts for the most important issues.  
* A practical CI/CD security gate design covering at least secrets, dependencies, IaC, containers, deployment approval, and exception handling.  
* A short rollout plan that avoids breaking every deployment on day one.

# **Part 3 \- Incident Response and Detection**

At 02:14 UTC, monitoring reports a burst of denied Kubernetes API requests followed by successful secret reads from the production cluster. Ten minutes later, the wallet database receives connections from an unusual pod. An AWS access key associated with the CI role was used from an unfamiliar IP address. A production deployment completed two hours earlier.

| Time | Observed event |
| :---- | :---- |
| 02:14 | Multiple denied list/get requests against Kubernetes secrets |
| 02:16 | Successful get requests for two secrets in the wallet namespace |
| 02:18 | New pod created using the callback-handler service account |
| 02:24 | Unexpected connections to the wallet database |
| 02:27 | CI-role access key observed from an unfamiliar source IP |

5. Describe your first 60 minutes: containment, evidence preservation, communication, and decisions that require explicit approval.  
6. List the data sources and queries you would use to establish scope and root cause.  
7. Define three durable detections or controls you would add after containment, including expected signal, likely false positives, and validation method.  
8. Explain your recovery and credential-rotation strategy and how you would determine that production is safe to resume.

# **Part 4 \- Purple-Team Validation**

Design one controlled, ATT\&CK-mapped security validation scenario for staging. It should test a realistic platform threat without creating unacceptable operational risk.

* Threat and ATT\&CK technique(s), with a short reason for the mapping.  
* Preconditions, authorised target allowlist, credentials, and environment restrictions.  
* Expected prevention and detection outcomes.  
* Telemetry and evidence to collect.  
* Human approval points, stop conditions, kill switch, and cleanup.  
* How the result becomes a remediation task, regression test, and retest record.

# **Part 5 \- External Penetration Test Readiness**

Create a brief pre-launch penetration-test scope. Include in-scope assets and roles, key attack surfaces, test accounts and data, exclusions, rules of engagement, escalation contacts, evidence expectations, severity and remediation rules, and retest acceptance criteria.

# **Submission Checklist**

* Architecture or trust-boundary diagram.  
* Eight-risk launch register and first-30-day priorities.  
* Review and remediation of the Terraform, Kubernetes, and GitLab snippets.  
* Incident-response and detection plan.  
* One controlled purple-team scenario.  
* External penetration-test scope.  
* Assumptions, trade-offs, unresolved questions, and material AI use disclosure.

| Final note: We will discuss your submission in a 60-minute technical interview. Be prepared to defend priorities, explain code changes, and adapt the design when constraints change. |
| :---- |

