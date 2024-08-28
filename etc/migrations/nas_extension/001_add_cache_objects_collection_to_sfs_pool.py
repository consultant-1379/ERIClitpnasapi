from litp.migration import BaseMigration
from litp.migration.operations import AddCollection

class Migration(BaseMigration):
    version = '1.15.3'
    operations = [ AddCollection('sfs-pool', 'cache_objects', 'sfs-cache'),]
