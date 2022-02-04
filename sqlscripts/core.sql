BEGIN;
--
-- Create model CVE
--
CREATE TABLE "core_cve" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "mitre_id" varchar(20) NOT NULL, "public_release_date" date NOT NULL, "base_score" decimal NOT NULL, "impact_score" decimal NOT NULL, "exploitability_score" decimal NOT NULL);
--
-- Create model RiskProfile
--
CREATE TABLE "core_riskprofile" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "severity" smallint unsigned NOT NULL CHECK ("severity" >= 0), "urgency" smallint unsigned NOT NULL CHECK ("urgency" >= 0), "summary" text NOT NULL, "impact" text NOT NULL, "support_url" varchar(200) NOT NULL, "cve_id" bigint NOT NULL REFERENCES "core_cve" ("id") DEFERRABLE INITIALLY DEFERRED);
--
-- Create model FirmwareReference
--
CREATE TABLE "core_firmwarereference" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "rollup_versions" bool NOT NULL, "affected_major" smallint unsigned NOT NULL CHECK ("affected_major" >= 0), "affected_minor" smallint unsigned NOT NULL CHECK ("affected_minor" >= 0), "affected_build" varchar(8) NOT NULL, "fixed_major" smallint unsigned NOT NULL CHECK ("fixed_major" >= 0), "fixed_minor" smallint unsigned NOT NULL CHECK ("fixed_minor" >= 0), "fixed_build" varchar(8) NOT NULL, "cve_id" bigint NOT NULL REFERENCES "core_cve" ("id") DEFERRABLE INITIALLY DEFERRED);
CREATE INDEX "core_riskprofile_cve_id_8b759c84" ON "core_riskprofile" ("cve_id");
CREATE INDEX "core_firmwarereference_cve_id_e836a6f1" ON "core_firmwarereference" ("cve_id");
COMMIT;
