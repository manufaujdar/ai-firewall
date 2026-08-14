# Compliance and deployment boundary

This repository does not provide legal compliance, certification, regulatory approval, or a
turnkey control for GDPR, HIPAA, PCI DSS, ISO 27001, SOC 2, or any other framework. Those outcomes
depend on organizational policy, lawful basis, contracts, identity controls, deployment topology,
logging, retention, incident response, and independent assessment.

Before deployment, document the data owner, controller/processor roles, approved AI providers,
data regions, retention rules, user notice and consent, exception workflow, incident owner, and
rollback authority. Do not inspect employee or customer traffic without appropriate legal and
workplace review. TLS interception requires especially careful authorization and key management.

Treat audit output as security telemetry. It intentionally excludes raw content but can still
reveal timing, destinations, rule categories, and activity patterns. Apply least privilege,
retention limits, integrity controls, and access review.
