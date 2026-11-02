-- ==============================================================================
-- ENTERPRISE ZERO-TRUST IDENTITY & ACCESS MANAGEMENT (IAM) DATABASE SCHEMA
-- Target Database: iam_secure_portal (MySQL 8.x / MariaDB 10.4+)
-- Designed for: University Final Defense (4.2 IT Degree)
-- Focus: Curbing Organization Network Breaches via Compromised Internal Credentials
-- ==============================================================================

CREATE DATABASE IF NOT EXISTS `iam_secure_portal` 
DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `iam_secure_portal`;

-- Disable foreign key checks for table creation
SET FOREIGN_KEY_CHECKS = 0;

-- -------------------------------------------------------------
-- 1. ROLES TABLE (Role-Based Access Control - RBAC)
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `roles` (
    `role_id` INT AUTO_INCREMENT PRIMARY KEY,
    `role_name` VARCHAR(50) NOT NULL UNIQUE,
    `description` VARCHAR(255) NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed Standard Enterprise Roles
INSERT INTO `roles` (`role_id`, `role_name`, `description`) VALUES
(1, 'Super Admin', 'Full administrative authorization across identities, telemetry, and RBAC governance'),
(2, 'Security Analyst', 'SOC incident response, telemetry investigation, and account suspension authority'),
(3, 'IAM Auditor', 'Read-only access to immutable security trails and compliance reporting'),
(4, 'Employee', 'Standard corporate user with basic resource access and mandatory MFA requirement')
ON DUPLICATE KEY UPDATE `role_name` = VALUES(`role_name`), `description` = VALUES(`description`);

-- -------------------------------------------------------------
-- 2. USERS TABLE (Identity Directory & Zero-Trust State)
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
    `user_id` INT AUTO_INCREMENT PRIMARY KEY,
    `first_name` VARCHAR(60) NULL,
    `last_name` VARCHAR(60) NULL,
    `department` VARCHAR(100) NOT NULL DEFAULT 'General Operations',
    `job_title` VARCHAR(100) NOT NULL DEFAULT 'Staff Analyst',
    `email` VARCHAR(150) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `mfa_secret` VARCHAR(64) NULL,
    `role` VARCHAR(50) NOT NULL DEFAULT 'Staff',
    `security_clearance` VARCHAR(20) NOT NULL DEFAULT 'Tier 1',
    `role_id` INT NOT NULL DEFAULT 4,
    `is_active` TINYINT(1) NOT NULL DEFAULT 1 COMMENT '1 = Active, 0 = Suspended/Locked',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_user_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`role_id`) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------------
-- 2b. API_KEYS TABLE (Programmatic Service Access Tokens)
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `api_keys` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `app_name` VARCHAR(100) NOT NULL,
    `api_key` VARCHAR(128) NOT NULL UNIQUE,
    `status` VARCHAR(20) NOT NULL DEFAULT 'Active',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------------
-- 3. PERMISSIONS TABLE
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `permissions` (
    `permission_id` INT AUTO_INCREMENT PRIMARY KEY,
    `permission_name` VARCHAR(80) NOT NULL UNIQUE,
    `description` VARCHAR(255) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------------
-- 4. ROLE_PERMISSIONS TABLE (Many-to-Many Mapping)
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `role_permissions` (
    `role_id` INT NOT NULL,
    `permission_id` INT NOT NULL,
    PRIMARY KEY (`role_id`, `permission_id`),
    CONSTRAINT `fk_rp_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`role_id`) ON DELETE CASCADE,
    CONSTRAINT `fk_rp_perm` FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`permission_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------------
-- 5. AUDIT_LOGS TABLE (Immutable SOC Audit Trail)
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `audit_logs` (
    `log_id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NULL,
    `action_type` VARCHAR(60) NOT NULL,
    `action_description` TEXT NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_action_type` (`action_type`),
    INDEX `idx_user_created` (`user_id`, `created_at`),
    INDEX `idx_ip_created` (`ip_address`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;
