import pathlib, csv, datetime
from django.core.management.base import BaseCommand, CommandError
from core.models import CVE, SysInfo

class Command(BaseCommand):
    help = 'Imports CVE data from Lexmark CVE.csv file'

    def add_arguments(self, parser):
        parser.add_argument('cvefile', nargs='+', type=str)
    
    def handle(self, *args, **options):
        file = pathlib.Path(options['cvefile'][0])

        with open(file, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)

            #CVE Number,CVSSv3 Base Score,Impact Subscore,Exploitability Subscore,Fixed FW,CVE Link,CVE Support URL,Description
            all_items = []
            failed = 0
            for row in reader:
                if row['Fixed FW'] != '' or row['CVSSv3 Base Score'] != '' or row['Exploitability Subscore'] != '' or row['Impact Subscore'] != '':
                    try:
                        item = CVE(
                            mitre_id=row['CVE Number'],
                            base_score=float(row.get('CVSSv3 Base Score', 0)),
                            impact_score=float(row.get('Impact Subscore', 0)),
                            exploitability_score=float(row.get('Exploitability Subscore', 0)),
                            short_description=row['Description'],
                            support_url=row['CVE Support URL']
                        )

                        all_items.append(item)
                    except Exception as ex:
                        self.stderr.write(self.style.ERROR(f'{row["CVE Number"]} failed: {ex}'))
                        failed += 1
        
        try:
            CVE.objects.all().delete()

            result = CVE.objects.bulk_create(all_items)
            self.stdout.write(self.style.SUCCESS(f'{len(result)} CVE records created ({failed} failures)'))
            self.stdout.write(self.style.WARNING('WARNING - Firmware References are now broken and need to be recomputed!!'))

            # update sysinfo record
            SysInfo.objects.first().cves_last_updated = datetime.datetime.now()
        except Exception as ex:
            self.stderr.write(self.style.ERROR(f'Failed to create CVE records: {ex}'))
