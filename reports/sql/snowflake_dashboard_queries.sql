-- ============================================================================
-- CDC-5: KUBERNETES SECURITY ASSESSMENT & 11-MODEL ML BENCHMARK
-- SNOWFLAKE SNOWSIGHT DASHBOARD SETUP QUERIES
-- ============================================================================
-- Database: K8S_SECURITY
-- Schema  : PUBLIC
-- Warehouse: COMPUTE_WH (Configured with X-Small & 60s Auto-Suspend)
-- ============================================================================

USE DATABASE K8S_SECURITY;
USE SCHEMA PUBLIC;
USE WAREHOUSE COMPUTE_WH;

-- ============================================================================
-- TILE 1: Executive KPI Cards (Single Values)
-- ============================================================================

-- Tile 1A: Average Fleet Security Score (Gauge or Scorecard)
SELECT 
    ROUND(AVG(SECURITY_SCORE), 1) AS "Average Security Score",
    100 AS "Max Score"
FROM K8S_FLEET_SECURITY;

-- Tile 1B: Total Fleet Size Assessed (Scorecard)
SELECT 
    COUNT(*) AS "Total Manifests & Clusters Assessed"
FROM K8S_FLEET_SECURITY;

-- Tile 1C: High-Risk Attack Surface Detected (Scorecard)
SELECT 
    SUM(PRIVILEGED_COUNT) AS "Privileged Workloads",
    SUM(CRITICAL_CVE_COUNT) AS "Critical CVEs (CVSS >= 9)",
    SUM(SECRET_COUNT) AS "Exposed Secrets"
FROM K8S_FLEET_SECURITY;

-- Tile 1D: Top Performing Machine Learning Model (Scorecard)
SELECT 
    MODEL_NAME AS "Best Model",
    ROUND(R2_SCORE, 3) AS "Top R2 Score",
    ROUND(RMSE, 2) AS "Lowest RMSE",
    CONCAT(ROUND(ACCURACY_PCT, 1), '%') AS "Accuracy"
FROM K8S_MODEL_BENCHMARK_11
WHERE R2_SCORE IS NOT NULL
ORDER BY R2_SCORE DESC
LIMIT 1;


-- ============================================================================
-- TILE 2: Fleet Risk Tier Distribution (Donut / Pie Chart)
-- ============================================================================
-- Chart Type : Donut Chart
-- Slice      : RISK_LEVEL
-- Metric     : CLUSTER_COUNT
SELECT 
    RISK_LEVEL,
    CLUSTER_COUNT,
    AVG_SECURITY_SCORE
FROM V_FLEET_RISK_DISTRIBUTION
ORDER BY AVG_SECURITY_SCORE ASC;


-- ============================================================================
-- TILE 3: 11-Model Machine Learning Matrix Benchmark (Bar / Column Chart)
-- ============================================================================
-- Chart Type : Grouped Bar Chart
-- X-Axis     : MODEL_NAME (or MODEL_ID)
-- Y-Axis     : R2_SCORE, RMSE
-- Series     : TRAIN_DOMAIN
SELECT 
    MODEL_ID,
    MODEL_NAME,
    TRAIN_DOMAIN,
    R2_SCORE,
    RMSE,
    ACCURACY_PCT,
    ARCHITECTURE_TIER
FROM V_MODEL_PERFORMANCE_LEADERBOARD
WHERE R2_SCORE IS NOT NULL
ORDER BY MODEL_ID ASC;


-- ============================================================================
-- TILE 4: Unsupervised Anomaly Detection Performance (Scorecard / Bar)
-- ============================================================================
-- Evaluates Isolation Forest against zero-day high-risk workloads
SELECT 
    MODEL_ID,
    MODEL_NAME,
    TRAIN_DOMAIN,
    ANOMALY_ROC_AUC AS "Anomaly ROC-AUC",
    OUTLIER_RECALL_PCT AS "Outlier Recall %"
FROM K8S_MODEL_BENCHMARK_11
WHERE ANOMALY_ROC_AUC IS NOT NULL;


-- ============================================================================
-- TILE 5: 56-Vulnerability Taxonomy by Defense Plane & Severity (Stacked Bar Chart)
-- ============================================================================
-- Chart Type : Stacked Bar Chart
-- X-Axis     : PLANE_NAME
-- Y-Axis     : CRITICAL_COUNT, HIGH_COUNT, MEDIUM_COUNT, LOW_COUNT
SELECT 
    PLANE_NAME,
    CRITICAL_COUNT,
    HIGH_COUNT,
    MEDIUM_COUNT,
    LOW_COUNT,
    TOTAL_VULNS
FROM V_PLANE_SEVERITY_SUMMARY
ORDER BY PLANE_NUMBER ASC;


-- ============================================================================
-- TILE 6: MITRE ATT&CK for Containers Threat Mapping (Table)
-- ============================================================================
-- Chart Type : Table
SELECT 
    VULN_ID,
    PLANE_NAME,
    NAME AS "Vulnerability Name",
    SEVERITY,
    MITRE_ATTACK_ID,
    STANDARD_REF,
    REMEDIATION
FROM K8S_VULNERABILITY_TAXONOMY_56
ORDER BY 
    CASE SEVERITY
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        ELSE 4
    END, VULN_ID ASC;


-- ============================================================================
-- TILE 7: Telemetry Radar: Top Vulnerability Drivers (Horizontal Bar Chart)
-- ============================================================================
-- Aggregates the most frequent security misconfigurations across all workloads
SELECT 
    'Privileged Containers' AS RISK_VECTOR, SUM(PRIVILEGED_COUNT) AS INCIDENT_COUNT FROM K8S_FLEET_SECURITY
UNION ALL
SELECT 'Execution as Root (UID 0)', SUM(ROOT_EXECUTION_COUNT) FROM K8S_FLEET_SECURITY
UNION ALL
SELECT 'HostPath Mounts', SUM(HOST_PATH_COUNT) FROM K8S_FLEET_SECURITY
UNION ALL
SELECT 'Dangerous Linux Capabilities', SUM(RISKY_CAPABILITY_COUNT) FROM K8S_FLEET_SECURITY
UNION ALL
SELECT 'Missing NetworkPolicies', SUM(MISSING_NETWORK_POLICIES) FROM K8S_FLEET_SECURITY
UNION ALL
SELECT 'Overpermissive Wildcard RBAC', SUM(WILDCARD_RBAC_RULES) FROM K8S_FLEET_SECURITY
UNION ALL
SELECT 'Cluster-Admin Bindings', SUM(CLUSTER_ADMIN_BINDINGS) FROM K8S_FLEET_SECURITY
UNION ALL
SELECT 'Runtime Falco Alerts', SUM(FALCO_ALERT_COUNT) FROM K8S_FLEET_SECURITY
ORDER BY INCIDENT_COUNT DESC;
