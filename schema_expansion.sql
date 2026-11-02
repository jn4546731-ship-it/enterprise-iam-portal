-- =====================================================================
-- Enterprise IAM Portal - Schema Expansion (Phase 4.2: RBAC & Vault)
-- Adds Department, Job Title, Functional Role, and Security Clearance
-- Creates API Key Management table
-- =====================================================================

USE `iam_secure_portal`;

-- 1. Alter users table to add enterprise attributes if not present
SET @dbname = DATABASE();
SET @tablename = "users";

-- Add department
SET @precheck = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND COLUMN_NAME = 'department');
SET @sql = IF(@precheck = 0, 'ALTER TABLE users ADD COLUMN department VARCHAR(100) NOT NULL DEFAULT "General Operations" AFTER last_name', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add job_title
SET @precheck = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND COLUMN_NAME = 'job_title');
SET @sql = IF(@precheck = 0, 'ALTER TABLE users ADD COLUMN job_title VARCHAR(100) NOT NULL DEFAULT "Staff Analyst" AFTER department', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add role (Admin, Staff, Auditor)
SET @precheck = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND COLUMN_NAME = 'role');
SET @sql = IF(@precheck = 0, 'ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT "Staff" AFTER job_title', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add security_clearance (Tier 1, Tier 2, Tier 3)
SET @precheck = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND COLUMN_NAME = 'security_clearance');
SET @sql = IF(@precheck = 0, 'ALTER TABLE users ADD COLUMN security_clearance VARCHAR(20) NOT NULL DEFAULT "Tier 1" AFTER role', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 2. Create api_keys table
CREATE TABLE IF NOT EXISTS `api_keys` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `app_name` VARCHAR(100) NOT NULL,
  `api_key` VARCHAR(128) NOT NULL UNIQUE,
  `status` VARCHAR(20) NOT NULL DEFAULT 'Active',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Set Administrator attributes to Tier 3 Top Secret clearance
UPDATE `users` 
SET `department` = 'Security Operations Center',
    `job_title` = 'Chief Information Security Officer (CISO)',
    `role` = 'Admin',
    `security_clearance` = 'Tier 3'
WHERE `user_id` = 1 OR `email` = 'admin@organization.com';

-- 4. Seed initial enterprise service API keys if empty
INSERT IGNORE INTO `api_keys` (`id`, `app_name`, `api_key`, `status`, `created_at`) VALUES
(1, 'SIEM Telemetry Collector', 'sec_live_9f82c448e8a1d723bfa9901416e012ac7d9e', 'Active', NOW()),
(2, 'Zero-Trust Gatekeeper Edge', 'sec_live_1b73e559f02c9182eaa0032517b123bd8f01', 'Active', NOW()),
(3, 'Audit Log Cold Storage (S3)', 'sec_live_a34c8901be82ff4710dcae987113bc62114a', 'Active', NOW());
