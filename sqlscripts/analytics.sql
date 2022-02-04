BEGIN;
--
-- Create model VulnerableDevice
--
CREATE TABLE "analytics_vulnerabledevice" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "serial_number" varchar(15) NOT NULL, "last_seen" datetime NOT NULL, "firmware_major" smallint unsigned NOT NULL CHECK ("firmware_major" >= 0), "firmware_minor" smallint unsigned NOT NULL CHECK ("firmware_minor" >= 0), "firmware_build" varchar(8) NOT NULL);
CREATE TABLE "analytics_vulnerabledevice_vulnerable_cves" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "vulnerabledevice_id" bigint NOT NULL REFERENCES "analytics_vulnerabledevice" ("id") DEFERRABLE INITIALLY DEFERRED, "cve_id" bigint NOT NULL REFERENCES "core_cve" ("id") DEFERRABLE INITIALLY DEFERRED);
CREATE UNIQUE INDEX "analytics_vulnerabledevice_vulnerable_cves_vulnerabledevice_id_cve_id_3b9d4c73_uniq" ON "analytics_vulnerabledevice_vulnerable_cves" ("vulnerabledevice_id", "cve_id");
CREATE INDEX "analytics_vulnerabledevice_vulnerable_cves_vulnerabledevice_id_1403f911" ON "analytics_vulnerabledevice_vulnerable_cves" ("vulnerabledevice_id");
CREATE INDEX "analytics_vulnerabledevice_vulnerable_cves_cve_id_58d1e80c" ON "analytics_vulnerabledevice_vulnerable_cves" ("cve_id");
COMMIT;
