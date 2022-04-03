import pathlib, csv, datetime
from django.core.management.base import BaseCommand, CommandError
from core.models import CVE, FirmwareReference, SysInfo
from api.views import FirmwareParser

class Command(BaseCommand):
    help = 'Imports CVE data from Lexmark CVE.csv file'

    def add_arguments(self, parser):
        parser.add_argument('cvefile', nargs='+', type=str)
    
    def handle(self, *args, **options):
        file = pathlib.Path(options['cvefile'][0])

        with open(file, mode='r', encoding='utf-8-sig') as csvfile:
            CVE.objects.all().delete()
            reader = csv.DictReader(csvfile)

            #CVE Number,CVSSv3 Base Score,Impact Subscore,Exploitability Subscore,Firmware Archs,Fixed FW,CVE Link,CVE Support URL,Description
            saved = 0
            failed = 0
            for row in reader:
                if row['Fixed FW'] != '' and row['CVSSv3 Base Score'] != '' and row['Exploitability Subscore'] != '' and row['Impact Subscore'] != '' and row['Firmware Archs'] != 'MVE':
                    try:
                        cve = CVE(
                            mitre_id=row['CVE Number'],
                            base_score=float(row.get('CVSSv3 Base Score', 0)),
                            impact_score=float(row.get('Impact Subscore', 0)),
                            exploitability_score=float(row.get('Exploitability Subscore', 0)),
                            short_description=row['Description'],
                            support_url=row['CVE Support URL']
                        )

                        cve.save()
                        saved += 1
                        self.stdout.write(self.style.SUCCESS(f'Saved {row["CVE Number"]}'))

                        # CL|WC|HS|PR|PDO
                        archs_types = {'CL': 'xml', 'WC': 'combo', 'HS': 'ucf'}
                        archs = row['Firmware Archs'].split('|')
                        fixed_versions = row['Fixed FW'].split('|')

                        if len(archs) == len(fixed_versions):
                            saved_refs = 0
                            for i in range(0, len(archs)):                            
                                arch_type = archs_types.get(archs[i], None)
                                
                                if arch_type is not None:
                                    fixed_ver = FirmwareParser(fixed_versions[i])

                                    if not fixed_ver.parsed:
                                        continue

                                    dt = FirmwareReference.DeviceType(arch_type)

                                    ref = FirmwareReference(
                                        cve = cve,
                                        device_type = dt,
                                        fixed_major = fixed_ver.major,
                                        fixed_minor = fixed_ver.minor,
                                        fixed_build = fixed_ver.build
                                    )

                                    ref.save()
                                    saved_refs += 1
                            
                            self.stdout.write(self.style.SUCCESS(f' - {saved_refs} firmware references created'))

                    except Exception as ex:
                        self.stderr.write(self.style.ERROR(f'{row["CVE Number"]} failed: {ex}'))
                        failed += 1
        
        SysInfo.objects.first().cves_last_updated = datetime.datetime.now()
        self.stdout.write(self.style.SUCCESS(f'{saved} CVE records created ({failed} failures)'))
