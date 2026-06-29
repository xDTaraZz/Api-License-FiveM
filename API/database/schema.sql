-- ============================================================================
--  NEXUS LICENSE API — Database schema (MySQL 8 / MariaDB 10.4+)
--  Run once:  mysql -u root -p < database/schema.sql
--  (or: npm run migrate  — which applies this file programmatically)
-- ============================================================================

CREATE DATABASE IF NOT EXISTS `nexus_license`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `nexus_license`;

-- ----------------------------------------------------------------------------
--  products
--  One row per script/product you sell. The `secret` is the shared HMAC key
--  that gets baked into that product's server.lua. Never expose it publicly.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `products` (
  `id`          VARCHAR(40)   NOT NULL,                 -- e.g. prod_a1b2c3
  `name`        VARCHAR(120)  NOT NULL,
  `secret`      CHAR(64)      NOT NULL,                 -- 32-byte hex HMAC key
  `created_at`  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_products_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
--  licenses
--  One row per customer key. `ip_locked` is NULL until the first successful
--  verify, at which point the connecting IP is bound to the token. Subsequent
--  requests from a different IP are rejected until an admin resets it.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `licenses` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `token`         VARCHAR(64)   NOT NULL,
  `product_id`    VARCHAR(40)   NOT NULL,
  `owner_name`    VARCHAR(120)  NULL,
  `owner_contact` VARCHAR(190)  NULL,                   -- discord / email / etc.
  `status`        ENUM('active','suspended','revoked') NOT NULL DEFAULT 'active',
  `ip_locked`     VARCHAR(45)   NULL,                   -- bound on first connect
  `last_ip`       VARCHAR(45)   NULL,
  `last_seen_at`  DATETIME      NULL,
  `expires_at`    DATETIME      NULL,                   -- NULL = lifetime
  `features`      JSON          NULL,                   -- arbitrary per-key flags
  `note`          VARCHAR(255)  NULL,
  `created_at`    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_licenses_token` (`token`),
  KEY `idx_licenses_product` (`product_id`),
  CONSTRAINT `fk_licenses_product`
    FOREIGN KEY (`product_id`) REFERENCES `products` (`id`)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
--  verify_logs
--  Audit trail of every verification attempt. Handy for spotting key sharing
--  (same token, many IPs) and for support.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `verify_logs` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `token`       VARCHAR(64)   NULL,
  `ip`          VARCHAR(45)   NULL,
  `action`      VARCHAR(40)   NULL,
  `result`      VARCHAR(40)   NOT NULL,                 -- ok / ip_mismatch / ...
  `message`     VARCHAR(190)  NULL,
  `created_at`  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_logs_token` (`token`),
  KEY `idx_logs_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE `products`
  ADD COLUMN IF NOT EXISTS `version` VARCHAR(20) NULL DEFAULT '1.0.0' AFTER `secret`;

ALTER TABLE `products`
  ADD COLUMN IF NOT EXISTS `ed_private` CHAR(64) NULL AFTER `version`,
  ADD COLUMN IF NOT EXISTS `ed_public`  CHAR(64) NULL AFTER `ed_private`;

CREATE TABLE IF NOT EXISTS `used_nonces` (
  `nonce`       VARCHAR(64)   NOT NULL,
  `expires_at`  DATETIME      NOT NULL,
  PRIMARY KEY (`nonce`),
  KEY `idx_nonce_exp` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `admin_audit` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `actor_fp`   VARCHAR(16)   NULL,
  `method`     VARCHAR(8)    NULL,
  `route`      VARCHAR(255)  NULL,
  `ip`         VARCHAR(45)   NULL,
  `status`     INT           NULL,
  `created_at` DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_admin_audit_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
