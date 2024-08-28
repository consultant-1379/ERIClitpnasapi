##############################################################################
# COPYRIGHT Ericsson AB 2021
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################


import unittest

from litp.core.model_manager import ModelManager
from litp.core.plugin_context_api import PluginApiContext
from litp.core.plugin_manager import PluginManager
from litp.extensions.core_extension import CoreExtension
from nas_extension.nas_extension import (NasExtension,
                                         SFSPropertiesValidator,
                                         NFSIPItemValidator,
                                         ips_overlap)


class TestNasExtensionBase(unittest.TestCase):

    def assertIn(self, obj1, obj2, msg=None):
        self.assertTrue(obj1 in obj2,
                        '"%s"   <-- is not in -->   "%s"' % (obj1, obj2) if not msg else msg)

    def assertErrorCount(self, errors, count, item=''):
        err_msg = "%s errors expected, got: %s" % (count, errors)
        if item:
            err_msg += " for %s" % item
        self.assertEquals(len(errors), count, err_msg)

    def run_all_validators(self, property, property_name, tests):
        for text, error_count in tests:
            errors = self._run_property_type_validators(property, property_name, text)
            self.assertErrorCount(errors, error_count, text)

    def check_validation_messages(self, property, property_name, tests):
        for text, msgs in tests:
            errors = self._run_property_type_validators(property,
                                                        property_name, text)
            self.assertErrorCount(errors, len(msgs), text)
            error_messages = [e.error_message.strip() for e in errors]
            diff = ', '.join(["'%s' != '%s'" % (e, m) for e, m in
                              zip(error_messages, msgs) if e != m])
            self.assertFalse(diff, "Different error messages: %s" % diff)

    def _run_property_type_validators(self, property_type,
                                      property_name, property_value):
        errors = []
        for validator in property_type.validators:
            err = validator.validate(property_value)
            if err:
                err.property_name = property_name
                errors.append(err)
        return errors

class TestNasExtension(TestNasExtensionBase):

    def setUp(self):
        self.model_manager = ModelManager()
        self.validator = self.model_manager.validator
        self.plugin_manager = PluginManager(self.model_manager)
        self.context = PluginApiContext(self.model_manager)

        self.core_ext = CoreExtension()
        self.nas_ext = NasExtension()

        self.prop_types = dict()
        for prop_type in self.nas_ext.define_property_types():
                self.prop_types[prop_type.property_type_id] = prop_type

        for prop_type in self.core_ext.define_property_types():
                self.prop_types[prop_type.property_type_id] = prop_type

        for ext in [self.core_ext, self.nas_ext]:
            self.plugin_manager.add_property_types(ext.define_property_types())
            self.plugin_manager.add_item_types(ext.define_item_types())
            if ext == self.core_ext:
                self.plugin_manager.add_default_model()

    def tearDown(self):
        pass

    def test_valid_path_string(self):
        #Note used by path and mount_point
        self.assertTrue('path_string' in self.prop_types)
        mountpoint_pt = self.prop_types['path_string']

        tests = [
            ('foo', 1),
            ('_foo bar', 1),
            ('/var', 0),
            ('/var/log/ltp', 0),
            ('/opt/va_ree', 0)
        ]
        self.run_all_validators(mountpoint_pt, "path_string", tests)

    def test_valid_provider(self):
        self.assertTrue('provider' in self.prop_types)
        provider = self.prop_types['provider']
        tests = [
            ('foo-1', 0),
            ('foo_1', 0),
            ('f_oo-1', 0),
            ('foo/1', 1),
            ('foo@1', 1),
            ('-foo', 1),
            ('foo-', 0),
            ('foo', 0),
            ('foo!1', 1),
            ('f-oo-1', 0),
            ('sfs1', 0),
            ('ipaddy1', 0)
        ]
        self.run_all_validators(provider, 'provider', tests)

    def test_valid_mount_options(self):
        self.assertTrue('mount_options' in self.prop_types)

        mount_options = self.prop_types['mount_options']

        tests = [
            (' ', 2),
            (',', 1),
            ('soft_sharecache', 1),
            ('soft sharecache', 2),
            ('foobar', 1),
            ('soft', 0),
            ('soft', 0),
            ('hard,,', 1),
            ('hard,soft', 1),
            ('hard,soft,ac,noac', 1),
            ('hard,ac,soft,noac', 1),
            ('noac,hard,ac,soft', 1),
            ('noac,sec=sys,hard,timeo=100,ac,soft', 1),
            ('sec=sys,noac,hard,timeo=100,ac,soft', 1),
            ('sec=sys,noac,hard,noresvport,timeo=100,ac,soft,resvport', 1),
            ('ac,noac', 1),
            ('bg,fg', 1),
            ('sharecache,nosharecache', 1),
            ('resport,noresport', 1),
            ('cto,nocto', 1),
            ('intr,nointr', 1),
            ('rsize=1024,rsize=1024', 1),
            ('soft,timeo=AA', 1),
            ('lookupcache=rubbish', 1),
            ('proto=rubbish', 1),
            ('sec=rubbish', 1),
            ('clientaddr=rubbish', 1),
            ('rubbish=rubbish', 1),
            ('timeo=AA', 1),
            ('timeo=11', 1),
            ('soft', 0),
            ('soft,timeo=100', 0),
            ('actimeo=100,retrans=5,rsize=1024', 0),
            ('acregmin=5,acregmax=9', 0),
            ('port=9999', 0),
            ('lookupcache=all', 0),
            ('clientaddr=109.109.109.109', 0),
            ('clientaddr=2001:cdba::3257:9652', 0),
            ('sec=sys', 0),
            ('retry=5', 0),
            ('acdirmin=60', 0),
            ('retrans=5', 0),
            ('rsize=1024', 0),
            ('wsize=2048', 0),
            ('proto=tcp', 0),
            ('vers=2', 0),
            ('vers=3', 0),
            ('vers=1', 1),
            ('vers=d', 1),
            ('proto=tcp', 0),
            ('defaults', 0),
            ('acdirmin=5,acdirmax=12', 0),
            ('minorversion=3', 0),
            ('acregmin=5,acregmax=12', 0),
            ('acregmin=20,acregmax=12', 1),
            ('acdirmin=20,acdirmax=5', 1)]

        self.run_all_validators(mount_options, 'mount_options', tests)

    def test_multiple_conflicting_mount_options(self):
        self.assertTrue('mount_options' in self.prop_types)
        mount_options = self.prop_types['mount_options']
        base_error_one = 'Conflicting nfs mount options input. Only one ' \
                         'option should be chosen from the following pair: %s'
        base_error = 'Conflicting nfs mount options input. Only one option ' \
                     'should be chosen from each of the following pairs: %s'
        error1 = base_error % '("soft", "hard") and ("ac", "noac")'
        error2 = base_error % '("soft", "hard"), ("ac", "noac") and ' \
                              '("resvport", "noresvport")'
        error3 = base_error_one % '("soft", "hard")'
        tests = [
            ('hard,soft,ac,noac', [error1]),
            ('hard,ac,soft,noac', [error1]),
            ('noac,hard,ac,soft', [error1]),
            ('noac,sec=sys,hard,timeo=100,ac,soft', [error1]),
            ('sec=sys,noac,hard,timeo=100,ac,soft', [error1]),
            ('noac,hard,noresvport,timeo=100,ac,soft,resvport', [error2]),
            ('hard,ac,soft', [error3]),
        ]
        self.check_validation_messages(mount_options, 'mount_options', tests)

    def test_multiple_conflicting_export_options(self):
        self.assertTrue('options' in self.prop_types)
        mount_options = self.prop_types['options']
        base_error = 'Conflicting export options input. Only one option ' \
                     'should be chosen from each of the following pairs: %s'
        error1 = base_error % '("rw", "ro") and ("sync", "async")'
        error2 = base_error % '("rw", "ro"), ("sync", "async") and ' \
                              '("subtree_check", "no_subtree_check")'
        tests = [
            ('ro,rw,sync,async', [error1]),
            ('rw,sync,ro,async', [error1]),
            ('async,rw,sync,ro', [error1]),
            ('sync,secure,async,rw,ro,fsid', [error1]),
            ('sync,secure,async,fsid,rw,wdelay,ro', [error1]),
            ('rw,subtree_check,sync,ro,async,no_subtree_check', [error2]),
        ]
        self.check_validation_messages(mount_options, 'mount_options', tests)

    def test_export_options(self):

        self.assertTrue('options' in self.prop_types)

        eo = self.prop_types['options']
        tests = [
            (' ', 2),
            (',', 1),
            ('secure,', 1),
            ('rubbish', 1),
            ('ro,ro', 1),
            ('ro,rw', 1),
            ('rw,async', 0)
        ]
        self.run_all_validators(eo, 'options', tests)

    def test_ipv4_address(self):
        self.assertTrue('ipv4_address' in self.prop_types)

        ip = self.prop_types['ipv4_address']
        tests = [
            (' ', 2),
            ('.', 1),
            ('255.255.255.256', 1),
            ('255.255.255.255!', 2),
            ('255.255.255.255', 0)
        ]
        self.run_all_validators(ip, 'ipv4_address', tests)

    def test_ipv4allowed_clients(self):

        self.assertTrue('ipv4allowed_clients' in self.prop_types)
        ip = self.prop_types['ipv4allowed_clients']

        tests = [
            (' ', 2),
            ('.', 1),
            ('255.255.255.256', 1),
            ('255.255.255.255!', 2),
            ('255.255.255.255', 0),
            ('255.255.255.255,34.54.13.143', 0),
            ('172.168.0.0/16', 0),
            ('172.168.0.0/24,172.168.0.1', 1),
            ('172.168.0.1,172.168.0.0/24', 1),
            ('172.168.10.0/0', 2),
            ('172.168.10.0/24!', 2),
            ('172.168.10.0/88', 1),
            ('172.168.10.10/24', 1),
            ('172.168.10.0/24,34.54.13.143', 0),
            ('34.54.13.143,172.168.10.0/24', 0)
        ]
        self.run_all_validators(ip, 'ipv4allowed_clients', tests)

        self.assertIn('IP address "34.54.13.143" is duplicated. IP address "34.54.13.1" is duplicated.'
                      ' IP address "34.54.13.1" overlaps with subnet "34.54.13.0/25". '
                      'Subnet "34.54.13.0/25" is duplicated.',
                      str(self._run_property_type_validators(
                          ip, 'ipv4allowed_clients',
                          '34.54.13.143,34.54.13.143,34.54.13.0/25,34.54.13.1,34.54.13.1,34.54.13.143,34.54.13.0/25')))
        self.assertIn('IP address "34.54.13.143" overlaps with subnet "34.54.13.0/24".',
                      str(self._run_property_type_validators(ip, 'ipv4allowed_clients',
                                                             '34.54.13.143,34.54.13.0/24')))

    def test_pool_name(self):

        self.assertTrue('pool_name' in self.prop_types)

        pool_name = self.prop_types['pool_name']

        tests = [
            (' ', 1),
            ('p', 1),
            ('pool.1', 1),
            ('pool?', 1),
            ('pool 1', 1),
            ('pool01234567890123456789012345678', 1),
            ('pool1', 0),
            ('pool-1', 0),
            ('1-pool', 0)
        ]
        self.run_all_validators(pool_name, 'pool_name', tests)

    def test_user_name(self):

        self.assertTrue('user_name' in self.prop_types)

        user_name = self.prop_types['user_name']
        tests = [
            ('Master', 1),
            ('master', 1),
            ('test_1', 0)
        ]
        self.run_all_validators(user_name, 'user_name', tests)

    def test_size(self):

        size = self.prop_types['size']
        tests = [
            ('22G', 0),
            ('2G', 0),
            ('0M', 1),
            ('9M', 1),
            ('0T', 1),
            ('0G', 1),
            ("M100", 1),
            ("100B", 1),
            ("a", 2)
        ]
        self.run_all_validators(size, 'size', tests)

    def test_path(self):
        self.assertTrue('export_path' in self.prop_types)
        export_path = self.prop_types['export_path']
        tests = [
            ('/vx/fsnamenotgreatert', 0),
            ('/vx/0123456789012345678901', 1),
            ('/vx/', 1),
            (None, 1),
            ('/vx/-fs1', 0),
            ('/vx/-', 0),
            ('/vx/abcde-karl^^', 1),
            ('/vx/ab^^e-karl1', 1),
            ('/vx/abcde-karl1', 0)
        ]
        self.run_all_validators(export_path, 'export_path', tests)

    def test_property_types_registered(self):
        prop_types_expected = [
                               'ipv4allowed_clients',
                               'options',
                               'mount_options',
                               'password_key',
                               'provider',
                               'pool_name',
                               'size',
                               'user_name',
                               'export_path',
                               'cache_name',
                               'nas_type',
                               'ports',
                               'sharing_protocols',
                               'san_pool',
                               'sp',
                               'subnet',
                               'gateway'
                               ]

        prop_types = [pt.property_type_id for pt in
                      self.nas_ext.define_property_types()]
        self.assertEquals(prop_types_expected, prop_types)

    def test_item_types_registered(self):
        item_types_expected = ['sfs-cache',
                               'sfs-pool',
                               'sfs-filesystem',
                               'sfs-export',
                               'sfs-service',
                               'nfs-service',
                               'sfs-virtual-server',
                               'nfs-mount',
                               ]
        item_types = [it.item_type_id for it in
                      self.nas_ext.define_item_types()]
        self.assertEquals(item_types_expected, item_types)

    def test_item_type_sfs_export_is_rest_updatable(self):
        sfs_export = [it for it in
                      self.nas_ext.define_item_types() if it.item_type_id == 'sfs-export']
        self.assertTrue(sfs_export[0].structure['options'].updatable_rest)

    def test_nas_type(self):
        self.assertTrue('nas_type' in self.prop_types)
        export_path = self.prop_types['nas_type']
        tests = [
            ('veritas', 0),
            ('unityxt', 0),
            ('bad', 1)
        ]
        self.run_all_validators(export_path, 'nas_type', tests)

    def test_ports_prop_type(self):
        sfs_virtual_server = [it for it in
                      self.nas_ext.define_item_types() if it.item_type_id == 'sfs-virtual-server']
        self.assertFalse(sfs_virtual_server[0].structure['ports'].updatable_rest)
        self.assertFalse(sfs_virtual_server[0].structure['ports'].updatable_plugin)
        self.assertTrue('ports' in self.prop_types)
        export_path = self.prop_types['ports']
        tests = [
            ('0,2', 0),
            ('1,3', 0),
            ('0,1', 0),
            ('0,3', 0),
            ('1,0', 0),
            ('1,2', 0),
            ('2,0', 0),
            ('2,1', 0),
            ('2,3', 0),
            ('3,0', 0),
            ('3,1', 0),
            ('3,2', 0),
            ('0,0', 1),
            ('1,1', 1),
            ('2,2', 1),
            ('3,3', 1),
            ('4,5', 1),
            ('4,5,6', 1),
            ('bad', 1),
            ('bad,bad', 1),
            ('bad,bad,bad', 1)
        ]
        self.run_all_validators(export_path, 'ports', tests)

    def test_sharing_protocols_prop_type(self):
        sfs_virtual_server = [it for it in
                      self.nas_ext.define_item_types() if it.item_type_id == 'sfs-virtual-server']
        self.assertTrue(sfs_virtual_server[0].structure['sharing_protocols'].updatable_rest)
        self.assertTrue(sfs_virtual_server[0].structure['sharing_protocols'].updatable_plugin)
        self.assertTrue('sharing_protocols' in self.prop_types)
        export_path = self.prop_types['sharing_protocols']
        # NFSv2 is not supported
        tests = [
            ('nfsv3', 0),
            ('nfsv4', 0),
            ('nfsv3,nfsv4', 0),
            ('nfsv2', 1)
        ]
        self.run_all_validators(export_path, 'sharing_protocols', tests)

    def test_san_pool_prop_type(self):
        sfs_virtual_server = [it for it in
                      self.nas_ext.define_item_types() if it.item_type_id == 'sfs-virtual-server']
        self.assertFalse(sfs_virtual_server[0].structure['san_pool'].updatable_rest)
        self.assertFalse(sfs_virtual_server[0].structure['san_pool'].updatable_plugin)
        self.assertTrue('san_pool' in self.prop_types)
        export_path = self.prop_types['san_pool']
        tests = [
            (' ', 1),
            ('p', 1),
            ('pool.1', 1),
            ('pool?', 1),
            ('pool 1', 1),
            ('pool01234567890123456789012345678', 1),
            ('pool1', 0),
            ('pool-1', 0),
            ('1-pool', 0)
        ]
        self.run_all_validators(export_path, 'san_pool', tests)

    def test_sp_prop_type(self):
        sfs_virtual_server = [it for it in
                      self.nas_ext.define_item_types() if it.item_type_id == 'sfs-virtual-server']
        self.assertFalse(sfs_virtual_server[0].structure['sp'].updatable_rest)
        self.assertFalse(sfs_virtual_server[0].structure['sp'].updatable_plugin)
        self.assertTrue('sp' in self.prop_types)
        export_path = self.prop_types['sp']
        tests = [
            ('spa', 0),
            ('spb', 0),
            ('bad', 1)
        ]
        self.run_all_validators(export_path, 'sp', tests)

    def test_subnet_prop_type(self):
        sfs_virtual_server = [it for it in
                      self.nas_ext.define_item_types() if it.item_type_id == 'sfs-virtual-server']
        self.assertFalse(sfs_virtual_server[0].structure['subnet'].updatable_rest)
        self.assertFalse(sfs_virtual_server[0].structure['subnet'].updatable_plugin)
        self.assertTrue('subnet' in self.prop_types)
        export_path = self.prop_types['subnet']
        tests = [
            (' ', 1),
            ('224.11.12.13/32', 0),
            ('10.11.12.0', 1),
            ('10.11.12.0/33', 1),
            ('bad', 1)
        ]
        self.run_all_validators(export_path, 'subnet', tests)

    def test_gateway_prop_type(self):
        sfs_virtual_server = [it for it in
                              self.nas_ext.define_item_types() if it.item_type_id == 'sfs-virtual-server']
        self.assertFalse(sfs_virtual_server[0].structure['gateway'].updatable_rest)
        self.assertFalse(sfs_virtual_server[0].structure['gateway'].updatable_plugin)
        self.assertTrue('gateway' in self.prop_types)

        ip = self.prop_types['gateway']
        tests = [
            (' ', 2),
            ('.', 1),
            ('255.255.255.256', 1),
            ('255.255.255.255!', 2),
            ('255.255.255.255', 0)
        ]
        self.run_all_validators(ip, 'gateway', tests)


class TestSFSPropertiesValidator(unittest.TestCase):
    """
        Test Class for 'sfs-service' Item Type Validator
    """
    def setUp(self):
        self.properties = {
            "name": 'sfs1',
            "management_ipv4": '10.10.10.10',
            "user_name": 'support',
            "password_key": 'key-for-sfs',
            }
        self.validator = SFSPropertiesValidator()
        self.error_dual_stack = 'Only property "management_ipv4" or ' \
            'property ' \
            '"management_ipv6" may be defined for an sfs-service but not both'
        self.error_attribute = lambda x: 'If the sfs-service is managed,' \
            ' the following properties should be added:' \
            ' property "%s". If the sfs-service is' \
            ' unmanaged, use only the property "name"' % x

    def test_missing_required_prop_for_managed_sfs_1(self):
        properties = self.properties.copy()
        del properties["user_name"]
        error = self.validator.validate(properties)
        self.assertEqual(
            error.error_message, self.error_attribute("user_name"))

    def test_missing_required_prop_for_managed_sfs_2(self):
        properties = self.properties.copy()
        del properties["management_ipv4"]
        error = self.validator.validate(properties)
        self.assertEqual(
            error.error_message, self.error_attribute("management_ipv4"))

    def test_missing_required_prop_for_managed_sfs_3(self):
        properties = self.properties.copy()
        del properties["password_key"]
        error = self.validator.validate(properties)
        self.assertEqual(
            error.error_message, self.error_attribute("password_key"))

    def test_missing_required_prop_for_managed_sfs_4(self):
        properties = self.properties.copy()
        del properties["password_key"]
        del properties["user_name"]
        del properties["management_ipv4"]
        error = self.validator.validate(properties)
        self.assertTrue(error is None)

    def test_ips_overlap(self):
        self.assertFalse(ips_overlap('1.1.1.1', '2.2.2.2'))
        self.assertTrue(ips_overlap('1.1.1.1', '1.1.1.0/24'))
        self.assertTrue(ips_overlap('1.1.1.0/24', '1.1.1.1'))
        self.assertFalse(ips_overlap('1.1.1.0/24', '2.2.2.0/24'))
        self.assertTrue(ips_overlap('1.1.1.0/24', '1.1.1.0/28'))

    def test_success(self):
        properties = self.properties.copy()
        error = self.validator.validate(properties)
        self.assertTrue(error is None)


class TestNFSIPItemValidator(unittest.TestCase):
    """
        Test Class for 'nfs-service' Item Type Validator
    """
    def setUp(self):
        self.properties = {
            "name": 'nfs1',
            "ipv4address": '10.10.10.5',
            "ipv6address": '21DA:D3::9C5A',
            }
        self.validator = NFSIPItemValidator()

    def test_no_ip_addresses_defined(self):
        properties = self.properties.copy()
        del properties["ipv4address"], properties["ipv6address"]
        error = self.validator.validate(properties)
        self.assertEqual(error.error_message,
                         'Either property "ipv4address" or '
                         'property "ipv6address" must be defined.')

    def test_only_ipv4_defined(self):
        properties = self.properties.copy()
        del properties["ipv6address"]
        error = self.validator.validate(properties)
        self.assertTrue(error is None)

    def test_only_ipv6_defined(self):
        properties = self.properties.copy()
        del properties["ipv4address"]
        error = self.validator.validate(properties)
        self.assertTrue(error is None)

    def test_success(self):
        properties = self.properties.copy()
        error = self.validator.validate(properties)
        self.assertTrue(error is None)


if __name__ == '__main__':
    unittest.main()
