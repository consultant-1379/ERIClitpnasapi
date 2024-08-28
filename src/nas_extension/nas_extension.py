##############################################################################
# COPYRIGHT Ericsson AB 2021
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import re
import netaddr

from litp.core.model_type import ItemType, Property, PropertyType, Collection
from litp.core.extension import ModelExtension
from litp.core.validators import ValidationError, PropertyValidator, \
    IPAddressValidator, ItemValidator, NetworkValidator
from litp.core.litp_logging import LitpLogger


log = LitpLogger()


def conflicting_options(choices, options, base_msg):
    conflicts = []
    for item in choices:
        if all(i in options for i in item):
            conflicts.append('("%s", "%s")' % item)
    if conflicts:
        second_msg = "Only one option should be chosen from each of the " \
                     "following pairs"
        if len(conflicts) == 1:
            conflicts = conflicts[0]
            second_msg = "Only one option should be chosen from the " \
                         "following pair"
        else:
            conflicts = "%s %s" % (', '.join(conflicts[:-1]),
                                   "and %s" % conflicts[-1])
        return '%s. %s: %s' % (base_msg, second_msg, conflicts)


class NasExtension(ModelExtension):
    """
    LITP Nas Model Extension.
    Allows for the configuration of external network attached storage.
    Defines nfs-service, sfs-service, sfs-filesystem, sfs-pool, sfs-cache,
    sfs-virtual-server, sfs-export and nfs-mount that enable the
    creation and mounting of shared file systems.
    """

    def define_property_types(self):

        property_types = []

        property_types.append(PropertyType("ipv4allowed_clients",
                    regex=r"^([0-9.]+(/[1-9][0-9]*){0,1}[,]?)+$",
                    validators=[IPv4AllowedClientsValidator()]))

        property_types.append(PropertyType("options",
                    regex=r"^[,_a-z]+$",
                    validators=[ExportOptionsValidator()]))

        property_types.append(PropertyType("mount_options",
                    regex=r"^[\w=,\.:]+$",
                    validators=[MountOptionsValidator()]))

        property_types.append(PropertyType("password_key",
                    regex=r"^.*$"))

        property_types.append(PropertyType("provider",
                                    regex=r"^[a-z][a-z0-9\-_]*$"))

        property_types.append(PropertyType("pool_name",
                    regex_error_desc='Accepts only alphanumeric characters '
                                     'and "-" and "_", minimum 2 '
                                     'maximum 31 characters.',
                    regex=r"^[a-zA-Z0-9\-_]{2,31}$"))

        property_types.append(PropertyType("size",
                    regex=r"^\d+[(G|M|T)]$",
                    validators=[SizeValidator()]))

        property_types.append(PropertyType("user_name",
                    regex=r"^.*$",
                    validators=[UserNameValidator()]))

        property_types.append(PropertyType("export_path",
                    validators=[PathValidator()]))

        property_types.append(PropertyType("cache_name",
                    regex_error_desc='Accepts only alphanumeric characters '
                                     'and "-" and "_", minimum 1 '
                                     'maximum 25 characters.',
                    regex=r"^[a-zA-Z0-9\-_]{1,25}$"))

        property_types.append(PropertyType("nas_type",
                    validators=[NasTypeValidator()]))

        property_types.append(PropertyType("ports",
                    validators=[PortsTypeValidator()]))

        property_types.append(PropertyType("sharing_protocols",
                    validators=[SharingProtocolsTypeValidator()]))

        property_types.append(PropertyType("san_pool",
                   regex_error_desc='Accepts only alphanumeric characters '
                                    'and "-" and "_", minimum 1 '
                                    'maximum 25 characters.',
                   regex=r"^[a-zA-Z0-9\-_]{2,31}$"))

        property_types.append(PropertyType("sp",
                    validators=[StorageProcessorTypeValidator()]))

        property_types.append(PropertyType("subnet",
                    validators=[SubnetTypeValidator()]))

        property_types.append(PropertyType("gateway",
                    regex=r"^[0-9\.]+$",
                    regex_error_desc='IPv4 Address must be specified',
                    validators=[GatewayTypeValidator()]))

        return property_types

    def define_item_types(self):
        """
        The item types
        """
        item_types = []
        item_types.append(
            ItemType("sfs-cache",
                item_description="This item represents"
                                 " the shared cache object"
                                 " for the SFS snapshot.",
                name=Property("cache_name",
                    prop_description="The name of the shared cache object "
                                     "that is used by the SFS snapshot.",
                    required=True,
                    updatable_rest=False),
        ))
        item_types.append(
            ItemType("sfs-pool",
                item_description="This item type represents"
                                 " the pre-configured pool(s)"
                                 " that file system(s) or cache object"
                                 " will be created in.",
                name=Property("pool_name",
                    prop_description="The name of the pool in which the "
                                     "file system(s) or cache object "
                                     "are to be created.",
                    required=True,
                    updatable_rest=False),
                file_systems=Collection("sfs-filesystem"),
                cache_objects=Collection("sfs-cache", max_count=1),
        ))
        item_types.append(
            ItemType("sfs-filesystem",
                item_description="This item type represents"
                                 " the file system"
                                 " that will be created on the SFS.",
                extend_item="file-system-base",
                path=Property('export_path',
                    prop_description="The path of the SFS file system "
                                     "that will be created on the SFS.",
                    required=True,
                    updatable_rest=False),
                size=Property("size",
                    prop_description="The size of the file system"
                                     " to be created.",
                    required=True),
                data_reduction=Property("basic_boolean",
                    prop_description="The parameter to enable/disable the"
                                     " data reduction for the file system."
                                     " Only used for unityxt",
                    required=False,
                    updatable_plugin=True,
                    updatable_rest=True),
                cache_name=Property('cache_name',
                    prop_description="The name of the shared cache object "
                                     "that is used by the SFS snapshot.",
                    required=False),
                backup_policy=Property('any_string',
                    prop_description="Used to specify how the file "
                           "system should be backed up (from snapshot or "
                           "direct).",
                    required=False,
                    configuration=False),
                snap_size=Property('basic_percent',
                    prop_description="The percentage of the file system size "
                                    "that is used to calculate the size of "
                                    "the sfs shared cache object.",
                    required=False,
                    configuration=False),
                provider=Property("provider",
                    prop_description="The sfs-virtual-server"
                                     " associated with the file system."
                                     " Only used for unityxt sfs-service",
                    required=False,
                    updatable_rest=True),
                exports=Collection("sfs-export"),
                validators=[]
        ))
        item_types.append(
            ItemType("sfs-export",
                item_description="This item represents"
                                 " export options and "
                                 " allowed clients"
                                 " of the underlying file system.",
                ipv4allowed_clients=Property("ipv4allowed_clients",
                    prop_description="A comma seperated list of IPv4 "
                                     "address(es)/subnet(s) that are "
                                     "allowed to access the export.",
                    required=True),
                options=Property("options",
                    prop_description="Options associated with the export.",
                    required=True,
                    updatable_rest=True),
        ))
        item_types.append(
            ItemType("sfs-service",
                item_description="This item type represents an"
                                 " SFS service",
                extend_item="storage-provider-base",
                name=Property('provider',
                    prop_description="The name of the SFS service.",
                    required=True,
                    updatable_rest=False),
                user_name=Property('user_name',
                    prop_description="The login username. Required only in "
                                     "the SFS managed scenario.",
                    required=False,
                    ),
                password_key=Property('password_key',
                    prop_description="The login password. Required only in "
                                     "the SFS managed scenario.",
                    required=False,
                    ),
                management_ipv4=Property("ipv4_address",
                    prop_description="The IPv4 address of the "
                                     "NAS console. Required only in the "
                                     "SFS managed scenario.",
                    required=False,
                    updatable_rest=False),
                nas_type=Property("nas_type",
                    prop_description="The type of SFS, "
                                     "veritas or unityxt, "
                                     "defaults to veritas",
                    required=False,
                    updatable_rest=False,
                    default="veritas"),
                virtual_servers=Collection("sfs-virtual-server"),
                pools=Collection("sfs-pool", max_count=999),
                validators=[SFSPropertiesValidator()]

        ))
        item_types.append(
            ItemType("nfs-service",
                item_description="This item type represents an"
                                 " NFS(Network File System) service.",
                extend_item="storage-provider-base",
                name=Property('provider',
                    prop_description="The name of the NFS service.",
                    required=True,
                    updatable_rest=False),
                ipv4address=Property("ipv4_address",
                    site_specific=True,
                    prop_description="The management IPv4 address of the NFS "
                                     "service.",
                    required=False,
                    updatable_rest=False),
                ipv6address=Property("ipv6_address",
                    site_specific=True,
                    prop_description="The management IPv6 address of the NFS "
                                     "service.",
                    required=False,
                    updatable_rest=False),
                validators=[NFSIPItemValidator()]
        ))
        item_types.append(
            ItemType("sfs-virtual-server",
                item_description="This item type represents"
                                 " an IPv4 address associated with"
                                 " the SFS server virtual interface.",
                name=Property('provider',
                    prop_description="The name of the virtual server.",
                    required=True,
                    updatable_rest=False),
                ipv4address=Property("ipv4_address",
                    site_specific=True,
                    prop_description="IPv4 address associated"
                                     " with the SFS server virtual interface.",
                    required=True,
                    updatable_rest=False),
                ports=Property("ports",
                    prop_description="The ports on the Unity XT SP that are"
                                     " connected to the Ethernet network."
                                     "The defaults are port 0 and port 2 on"
                                     " each SP. This property is only present"
                                     " and required for the unityxt NAS type.",
                    required=False,
                    updatable_rest=False),
                sharing_protocols=Property("sharing_protocols",
                    prop_description="The sharing protocol used to share"
                                     " filesystems from the NFS server."
                                     "NFSv3 and NFSv4 are supported."
                                     "This property is only present"
                                     " and required for the unityxt NAS type.",
                    required=False,
                    updatable_plugin=True,
                    updatable_rest=True),
                san_pool=Property("san_pool",
                    prop_description="SAN storage pool that the NAS server"
                                     " binds to. This property is only present"
                                     " and required for the unityxt NAS type.",
                    required=False,
                    updatable_rest=False),
                sp=Property("sp",
                    prop_description="SAN SP that the NAS server binds to."
                                     " This property is only present"
                                     " and required for the unityxt NAS type.",
                    required=False,
                    updatable_rest=False),
                subnet=Property("network",
                    prop_description="The network which the NAS is connected"
                                     "to.",
                    required=False,
                    updatable_rest=False),
                gateway=Property("ipv4_address",
                    prop_description="The NAS network gateway IP.",
                    required=False,
                    updatable_rest=False),
                ndmp_password_key=Property("password_key",
                    prop_description="NDMP password key. This property is only"
                                     " present and required for the unityxt"
                                     " NAS type.",
                    required=False,
                    updatable_rest=False)
        ))
        item_types.append(
            ItemType("nfs-mount",
                extend_item="file-system-base",
                item_description="This item type represents"
                                 " a client-side NFS(Network File System).",
                export_path=Property("path_string",
                    prop_description="The name of the export to be mounted.",
                    required=True,
                    updatable_rest=False),
                network_name=Property('basic_string',
                    prop_description="The network interface through which"
                    " the share is mounted. This property must be set to"
                    " the network which provides the most direct route to"
                    " the relevant NAS server.",
                    required=True,
                    updatable_rest=True),
                provider=Property("provider",
                    prop_description="The nfs-service or sfs-virtual-server"
                                     " associated with the nfs export.",
                    required=True,
                    updatable_rest=True),
                mount_point=Property("path_string",
                    prop_description="The mount point directory.",
                    required=True,
                    updatable_rest=False),
                mount_options=Property("mount_options",
                    prop_description="Options connected with the NAS client.",
                    required=False,
                    default='defaults',
                    updatable_plugin=True,
                    updatable_rest=False),
                device_path=Property("any_string",
                    prop_description="The ip and export that the nfs-mount "
                        "is mounted through in a dual stack scenario.",
                    required=False,
                    updatable_plugin=True,
                    updatable_rest=False),

        ))
        return item_types


class DebuggerMixin(object):

    def _debug(self, preamble, msg):
        log.trace.debug("%s: %s" % (preamble, msg))


def ips_overlap(ip1, ip2):
    # This method is used in nas_plugin also
    # if subnets
    if '/' in ip1 and '/' in ip2:
        subnet_1 = netaddr.IPNetwork(ip1)
        subnet_2 = netaddr.IPNetwork(ip2)
        return subnet_1 in subnet_2 or subnet_2 in subnet_1
    elif '/' in ip1:
        subnet_1 = netaddr.IPNetwork(ip1)
        ip_2 = netaddr.IPAddress(ip2)
        return ip_2 in subnet_1
    elif '/' in ip2:
        ip_1 = netaddr.IPAddress(ip1)
        subnet_2 = netaddr.IPNetwork(ip2)
        return ip_1 in subnet_2
    else:
        return ip1 == ip2


class SFSPropertiesValidator(ItemValidator, DebuggerMixin):

    """
    Custom ItemValidator for ''sfs-service' item type.

    Ensures that a managed 'sfs-service' has all the
    following properties: 'user_name', 'password_key',
    'management_ipv4'
    """

    def validate(self, properties):

        preamble = 'SFSPropertiesValidator '

        error_msgs = []
        missing_props = []
        expected_fields = []
        managed_props = [properties.get("management_ipv4"),
                         properties.get("user_name"),
                         properties.get("password_key")]

        if any(managed_props):
            expected_fields = ['user_name', 'password_key', 'management_ipv4']

        actual_fields = set(properties.keys()) & set(expected_fields)

        if actual_fields:
            for prop in expected_fields:
                if prop not in actual_fields:
                    missing_props.append(prop)
            if missing_props:
                msg = 'If the sfs-service'\
                      ' is managed, the following properties'\
                      ' should be' \
                      ' added: %s. If the' \
                      ' sfs-service is unmanaged, use only the' \
                      ' property "name"' \
                      % (', '.join(\
                          ['property "%s"' % p for p in missing_props]))
                error_msgs.append(msg)
                self._debug(preamble, msg)

        if error_msgs:
            message = ' '.join(error_msgs)
            return ValidationError(
                            error_message=message)


class UserNameValidator(PropertyValidator, DebuggerMixin):

    """
    Custom PropertyValidator for the 'user_name'
    property, which is a property of the 'sfs-service'
    item type. Ensures the property is not allowed to
    be defined with the value 'master'.
    """

    def validate(self, property_value):

        preamble = 'UserNameValidator '

        error_msg = '"master" is not an allowed value'

        if property_value is not None:
            if property_value.lower() == "master":
                self._debug(preamble, error_msg)
                return ValidationError(
                property_name="user_name",
                error_message=error_msg)


class SizeValidator(PropertyValidator, DebuggerMixin):

    """
    Custom PropertyValidator for the 'size'
    property which is a property of the 'sfs-filesystem'
    item type.

    Ensures the property adheres to the
    following rules:

    - One or more digits followed by one of the letters \
          M, G or T (example 1G)
    - Minimum size 10M
    """

    def validate(self, property_value):

        preamble = 'SizeValidator '

        error_msg = ''

        if property_value is not None:
            search_digit = re.search(r'\d+', property_value)
            if search_digit is None:
                return ValidationError(
                    property_name="size",
                    error_message=error_msg)
            num = int(search_digit.group(0))
            if 'M' in property_value:
                if num < 10:
                    error_msg = 'Minimum value is 10M'
                    self._debug(preamble, error_msg)
            elif 'G' in property_value or 'T' \
                 in property_value:
                if num == 0:
                    error_msg = 'Value can not be zero'
                    self._debug(preamble, error_msg)

        if error_msg:
            return ValidationError(
                property_name="size",
                error_message=error_msg)


class NFSIPItemValidator(ItemValidator, DebuggerMixin):

    """
    Custom ItemValidator for 'nfs-service'  item type.

    Ensures that at least one of 'ipv4_address' or 'ipv6_address'
    properties are present when creating an 'nfs-service'
    """

    def validate(self, properties):

        preamble = 'NFSIPItemValidator '

        if properties.get("ipv4address") is None and \
           properties.get("ipv6address") is None:
            error_msg = 'Either property "ipv4address" or ' \
                        'property "ipv6address" must be defined.'
            self._debug(preamble, error_msg)
            return ValidationError(
                property_name='ipv4address',
                error_message=error_msg)


class IPv4AllowedClientsValidator(PropertyValidator):

    """
    Custom PropertyValidator for 'ipv4allowed_clients'
    property which is a property of the sfs-export
    item type. Ensures the 'ipv4allowed_clients' property
    is a comma separated list of unique and valid IPv4 addresses/subnets
    or a single valid IPv4 address/subnet. It will not allow
    a comma at the beginning or end nor will it
    allow any other invalid characters including
    whitespaces.
    """

    def validate(self, property_value):

        error_msgs = self._allowed_clients_are_valid(property_value)

        if error_msgs:
            return ValidationError(
                property_name="ipv4allowed_clients",
                error_message='. '.join(error_msgs) + ".")

    @classmethod
    def _allowed_clients_are_valid(cls, property_value):

        if not property_value:
            return ['Only accepts a ' \
                   'list of valid IPv4 addresses or subnets '\
                   'separated ' \
                   'by single commas.']

        if not property_value[0].isdigit() or not property_value[-1].isdigit():
            return ['The list of comma separated IPv4 address(es) '
                    'or subnet(s) should begin and end with a digit.']

        def check_ip(ip):
            validator = IPAddressValidator("4")
            network_validator = NetworkValidator()
            generic_msg = '"%s" is invalid, only accepts a ' \
                       'list of valid IPv4 address(es)/subnet(s) ' \
                       'separated by single commas.' % ip
            subnet_mask_msg = '"%s" is an invalid value for a subnet' % ip
            if '/' not in ip:
                if validator.validate(ip) is not None:
                    return generic_msg
            else:
                if network_validator.validate(ip) is not None:
                    return generic_msg
                else:
                    subnet = netaddr.IPNetwork(ip)
                    if subnet.network != subnet.ip:
                        return subnet_mask_msg
            return None

        def valid_ip(ip):
            validator = IPAddressValidator("4")
            network_validator = NetworkValidator()
            if not '/' in ip:
                if validator.validate(ip) is not None:
                    return False
            else:
                if network_validator.validate(ip) is not None:
                    return False
                else:
                    subnet = netaddr.IPNetwork(ip)
                    if subnet.network != subnet.ip:
                        return False
            return True
        stripped_ips = [x.strip() for x in property_value.split(',')
                        if x and not x.isspace()]

        for ip in stripped_ips:
            msg = check_ip(ip)
            if msg:
                return [msg]
            if not valid_ip(ip):
                return '"%s" is invalid, only accepts a ' \
                       'list of valid IPv4 addresses/subnets separated ' \
                       'by single commas. ' % ip

        return cls.get_duplicate_ips(stripped_ips)

    @classmethod
    def get_duplicate_ips(cls, ips):
        """
        check if there are duplicated ips/subnets in a list
        @ips: list, ips/subnets to test
        @return: error messages for duplicated/overlapped ips/subnets
        """
        msgs = []
        warned_ips_duplicate = set()
        warned_ips_overlap = set()

        def generate_error_message(ip, other_ip):
            messages = []
            if '/' in ip:
                first_type = "Subnet"
            else:
                first_type = "IP address"
            if ip == other_ip:
                if ip not in warned_ips_duplicate:
                    messages.append(
                        '{first_type} "{ip}" is duplicated'.format(
                        first_type=first_type, ip=ip))
                warned_ips_duplicate.add(ip)
            else:
                if ip not in warned_ips_overlap:
                    messages.append(
                        '{first_type} "{ip}" overlaps with subnet'
                        ' "{other_ip}"'.format(
                        first_type=first_type, ip=ip, other_ip=other_ip))
                warned_ips_overlap.add(ip)
            return messages
        # changing the list into a sequence that will first have ips and
        # then will have the subnets
        _ips = [ip for ip in ips if not '/' in ip]
        subnets = [subnet for subnet in ips if '/' in subnet]
        ips = _ips + subnets
        for index, ip in enumerate(ips):
            other_ips = (
                other_ip for other_ip in ips[index + 1:]
                if ips_overlap(ip, other_ip))
            for other_ip in other_ips:
                msgs += generate_error_message(ip, other_ip)
        return msgs


class PathValidator(PropertyValidator, DebuggerMixin):
    """
    Custom PropertyValidator for 'path' \
    property of the 'sfs-filesystem' item type.

    - Absolute length of 'path' on 'sfs-filesystem' is 25 characters

    - 'path' property on 'sfs-filesystem' must begin with /vx/ \
       (first 4 characters of 25)

    - The remaining 21 characters of 'path' on 'sfs-filesystem' \
       is composed  of alphanumeric values, underscores and hyphens
    """

    def validate(self, property_value):
        preamble = 'PathValidator '
        error_msgs = []

        if property_value is None:
            error_msgs.append('Has not been defined')
        else:
            validation_methods = [
                self._validate_path_length,
                self._validate_filesystem_name
            ]
            for method in validation_methods:
                error_msg = method(property_value)
                if error_msg:
                    error_msgs.append(error_msg)

        self._debug(preamble, error_msgs)

        if error_msgs:
            msg = ' '.join(error_msgs)
            return ValidationError(
                    property_name="path",
                    error_message=msg)

    def _validate_path_length(self, property_value):
        """
        Method validates that the the length of the path
        is 25 characters or less
        """

        preamble = '_validate_path_length '

        error_msg = ''
        if len(property_value) > 25:
            error_msg = 'Should not be greater than 25'\
                        ' characters in length. '
            self._debug(preamble, error_msg)

        return error_msg

    def _validate_filesystem_name(self, property_value):
        """
        Method validates that the file system path
        is defined with alphanumeric, hypens
        or underscore characters only
        """

        preamble = '_validate_filesystem_name'

        error_msg = ''

        fs_name = property_value.split('/')[-1]

        if fs_name is '':
            error_msg = 'Property "path" should be defined ' \
                        'as follows: ' \
                        '</vx/><filesystem_name>'
            self._debug(preamble, error_msg)
        else:
            if re.match('^[A-Za-z_\\-0-9]+$', fs_name) is None:
                error_msg += 'The file system path "%s" should contain ' \
                             'alphanumeric characters, hyphens or' \
                             ' underscores only. ' % fs_name
                self._debug(preamble, error_msg)
        return error_msg


class ExportOptionsValidator(PropertyValidator):

    """
    Custom PropertyValidator for 'options'
    property of the sfs-export item type.

    Ensures the 'options' property is valid. 'options' is a comma seperated
    list of applicable options, with no spaces between list entries.
    One option from each of the following pairs is allowed:

    ('rw','ro'), ('sync',async'), ('secure','insecure'),
    ('secure_locks','insecure_locks'),
    ('root_squash',no_root_squash'), ('wdelay','no_wdelay'),
    ('subtree_check','no_subtree_check')

    - rw - grants read and write permission to the directory (including all \
    files under the directory) that reside on the exported directory's file \
    system. Hosts mounting this directory can make changes to it. This is \
    mutually exclusive with the ro option.

    - ro - grants read-only permission to the directory. Hosts mounting this\
    directory are not able to change it. This is mutually exclusive with\
    the rw option.

    - sync - grants synchronous write access to the directory. It forces the\
    server to perform a disk write before the request is considered \
    complete. This is mutually exclusive with the async option.

    - async - grants asynchronous write access to the directory. It allows the\
    server to write data to the disk when appropriate. This is mutually\
    exclusive with the sync option.

    - secure - grants secure access to the directory. It requires clients to \
    originate from a secure port, where a secure port is between 1-1024. This \
    is mutually exclusive with the insecure option.

    - insecure - grants insecure access to the directory. It permits client \
    requests to originate from unprivileged ports (those above 1024). \
    If the nfs server is planned to be used by any clients behind \
    a NAT device or environment, this option is typically needed for the \
    nfs server in most cases. Otherwise, any connection from the NATed \
    clients will be refused. This is mutually exclusive with \
    the secure option.

    - secure_locks - requires authorisation of all locking requests. This \
    is mutually exclusive with the insecure_locks option.

    - insecure_locks - some NFS clients do not send credentials with lock \
    requests and work incorrectly with secure_locks, in which \
    case you can only lock world-readable files. If you have such clients,\
    use the insecure_locks option. This is mutually exclusive with the \
    secure_locks option.

    - root_squash - prevents the root user on an NFS client from having root\
    privileges on an NFS mount. This effectively squashes the power of the \
    remote root user to the lowest local user, preventing remote root users \
    from acting as though they were the root user on the local system. \
    This is mutually exclusive with the no_root_squash option.

    - no_root_squash - allows root users on the NFS client to have root \
    privileges on the NFS server. This is mutually exclusive with the \
    root_squash option.

    - wdelay - causes the NFS server to delay writing to the disk if another\
    write request is imminent. This can improve performance by reducing \
    the number of times the disk must be accessed by separate write \
    commands. This is mutually exclusive with the no_wdelay option.

    - no_wdelay - imposes no delay in writing to the disk. This is mutually\
    exclusive with the wdelay option.

    - subtree_check - verifies that the requested file is in an exported \
    subdirectory. If this option is not enabled, the only verification is\
    that the file is in an exported file system. This is mutually exclusive\
    with the no_subtree_check option.

    - no_subtree_check - subtree checking can produce problems if a requested\
    file is renamed while the client has the file open. One such situation is\
    the export of the home directory. If many of these types of situations are\
    anticipated, set no_subtree_check. Most other situations are best handled\
    with subtree_check. This is mutually exclusive with the subtree_check \
    option.

    - fsid - allows the FileStore administrator to associate a specific number\
    as fsid with the share.

    """

    def validate(self, property_value):

        error_msgs = []

        export_options1 = ['rw', 'sync', 'secure', 'secure_locks',
                'root_squash', 'wdelay', 'subtree_check', 'fsid']

        export_options2 = ['ro', 'async', 'insecure',
                       'insecure_locks', 'no_root_squash',
                        'no_wdelay', 'no_subtree_check']

        options = [x.strip(',').strip() for x in \
                    property_value.split(',') \
                    if x and not x.isspace()]

        export_choices = zip(export_options1, export_options2)

        if not property_value:
            msg = "Not given. "
            error_msgs.append(msg)

        else:
            msg = self._check_string_format(property_value)
            if msg:
                error_msgs.append(msg)

            msg = self._check_duplicate_options(options)
            if msg:
                error_msgs.append(msg)

            for o in options:
                msg = '"%s" is an invalid option. ' % o
                if o not in export_options1 + export_options2:
                    error_msgs.append(msg)

            msg = self._check_conflicting_options(export_choices, options)
            if msg:
                error_msgs.append(msg)

        if error_msgs:
            msg = ' '.join(error_msgs)
            return ValidationError(
                            property_name="options",
                            error_message=msg)

    @staticmethod
    def _check_duplicate_options(options):
        if len(options) > len(set(options)):
            duplicates = set([x for x in \
            options if options.count(x) > 1])
            msg = ' '.join(duplicates) + " are " \
                "duplicate options. "
            return msg

    @staticmethod
    def _check_conflicting_options(choices, options):
        base_msg = 'Conflicting export options input'
        return conflicting_options(choices, options, base_msg)

    @staticmethod
    def _check_string_format(property_value):
        if not property_value[0].isalpha() \
            or not property_value[-1].isalpha():
            msg = "Invalid format to string. " \
                  "Remove any whitespace or punctuation " \
                  "from start or end of string. "
            return msg


class MountOptionsValidator(PropertyValidator):

    """
    Ensures that the following validation is applied to the values of the \
'mount_options' property.  \
    The following are valid options (if =n is specified, the option must \
have a numerical value):

    soft, hard, ac, noac, bg, fg, defaults, sharecache, nosharecache, \
resvport, noresvport, intr, nointr, cto, nocto, timeo=n, actimeo=n, \
retrans=n, rsize=n, wsize=n, acregmin=n, acregmax=n, acdirmin=n, retry=n, \
minorversion=n, port=n, proto=netid(see below), lookupcache=mode(see below), \
clientaddr=IP(see below), sec=mode(see below), lock, nolock, noexec, nosuid, \
vers=n(see below)

    - "clientaddr": must be a valid IP Address (IPv4 or IPv6)

    - "lookupcache": the value must be one \
of the following: none|all|pos|positive

    - "sec": the value must be one of the following: none|sys|krb5|\
krb5i|krb5p|lkey|lkeyp|spkm|spkmi|spkmp

    - "timeo": can only be used when the option "soft" is specified

    - "proto": the value must be one of the following: tcp|tcp6|rdma|udp|udp6

    - "vers": the value must be one of 2 or 3

    The following options conflict and will throw a validation error if input
    together:

    ("soft", "hard"), ("ac", "noac"),
    ("bg", "fg"), ("sharecache", "nosharecache"),
    ("resvport", "noresvport"), ("intr", "nointr"),
    ("lock", "nolock"), ("cto", "nocto")
    """

    def validate(self, property_value):

        error_msgs = []

        mount_options = []

        if property_value:
            if (not property_value[0].isalpha()
            or (not property_value[-1].isdigit()
            and not property_value[-1].isalpha())):
                msg = "Invalid format to string. " \
                      "Remove any whitespace or punctuation " \
                      "from start or end of string. "
                error_msgs.append(msg)

            options = [x.strip(',').strip() for x \
                       in property_value.split(',')
                       if x and not x.isspace()]

            for word in options:
                value = word.split('=')
                if value and value[0] not in mount_options:
                    mount_options.append(value[0])
                else:
                    msg = '"%s" has been entered more than once.' % value[0]
                    error_msgs.append(msg)
                if len(value) > 1:

                    validation_methods = [self._mount_option_is_valid(value),
                    self._compare_acregmin_acregmax(value, property_value),
                    self._compare_acdirmin_acdirmax(value, property_value),
                    self._option_has_value(value),
                    self._sec_option_value_is_valid(value),
                    self._proto_option_value_is_valid(value),
                    self._lookupcache_has_valid_parameter(value),
                    self._clientaddr_has_valid_ip(value),
                    self._timeo_option_is_valid(value, property_value),
                    self._vers_option_value_is_valid(value)]

                    for message in validation_methods:
                        if message is not None:
                            error_msgs.append(message)

                else:
                    validation_methods = [self._check_single_option(value),
                    self._contrast_mount_options(property_value)]
                    for message in validation_methods:
                        if message is not None and message not in error_msgs:
                            error_msgs.append(message)

            if error_msgs:
                msg = ' '.join(error_msgs)
                return ValidationError(
                            property_name="mount_options",
                            error_message=msg)

    @staticmethod
    def _vers_option_value_is_valid(value):
        regex = re.compile('(vers)')
        find = re.match(regex, value[0])
        if find is not None:
            if value[1].isdigit() and not 2 <= int(value[1]) <= 3:
                return 'The value "%s" for "vers" should be either '\
                        '"2" or "3".' % value[1]

    @staticmethod
    def _compare_acregmin_acregmax(value, property_value):
        if value[0] == "acregmin":
            options = [x.strip(',').strip() for x \
                   in property_value.split(',')
                   if x and not x.isspace()]
            for word in options:
                if "acregmax" in word:
                    acregmax_option = word.split('=')
                    if value[1].isdigit() and \
                            acregmax_option[1].isdigit():
                        if int(value[1]) > int(acregmax_option[1]):
                            return 'The value entered for the "acregmin" ' \
                            'option exceeds the value entered for "acregmax". '

    @staticmethod
    def _compare_acdirmin_acdirmax(value, property_value):
        if value[0] == "acdirmin":
            options = [x.strip(',').strip() for x \
                   in property_value.split(',')
                   if x and not x.isspace()]
            for word in options:
                if "acdirmax" in word:
                    acdirmax_option = word.split('=')
                    if value[1].isdigit() and \
                            acdirmax_option[1].isdigit():
                        if int(value[1]) > int(acdirmax_option[1]):
                            return 'The value entered for the "acdirmin" ' \
                            'option exceeds the value entered for "acdirmax". '

    @staticmethod
    def _clientaddr_has_valid_ip(value):

        regex = re.compile('(clientaddr)')
        find = re.match(regex, value[0])
        if find is not None:
            validator = IPAddressValidator("both")
            if validator.validate(value[1]) is not None:
                msg = '"clientaddr" option: "%s" is an invalid ' \
                      'ipv4 or ipv6 address.' % value[1]
                return msg

    @staticmethod
    def _check_single_option(value):
        regex = re.compile(r'^(soft|hard|' \
                                 r'ac|noac|' \
                                 r'bg|fg|' \
                                 r'defaults|' \
                                 r'lock|' \
                                 r'nolock|' \
                                 r'noexec|' \
                                 r'nosuid|' \
                                 r'sharecache|nosharecache|' \
                                 r'resvport|noresvport|' \
                                 r'intr|nointr|' \
                                 r'cto|nocto)$')
        find = re.match(regex, value[0])

        if find is None:
            msg = '"%s" is invalid. ' % value[0]
            return msg

    @staticmethod
    def _lookupcache_has_valid_parameter(value):

        regex = re.compile('(lookupcache)')
        find = re.match(regex, value[0])

        if find is not None:
            regex = re.compile('(none|all|pos|positive)')
            if re.match(regex, value[1]) is None:
                msg = '"%s" is an invalid "lookupcache" option. ' \
                      'Valid values are (none|all|pos|positive)'\
                      % value[1]
                return msg

    @staticmethod
    def _sec_option_value_is_valid(value):

        regex = re.compile('(sec)')
        find = re.match(regex, value[0])

        if find is not None:
            regex = re.compile(r'\b(none|sys|krb5|krb5i|krb5p'
                        r'|lkey|lkeyp|spkm|spkmi|spkmp)\b')
            if re.match(regex, value[1]) is None:
                msg = '"%s" is an invalid "sec" value. ' \
                    'Valid values are (none|sys|krb5|krb5i|krb5p' \
                    '|lkey|lkeyp|spkm|spkmi|spkmp)' % value[1]
                return msg

    @staticmethod
    def _proto_option_value_is_valid(value):

        regex = re.compile('(proto)')
        find = re.match(regex, value[0])

        if find is not None:
            regex = re.compile(r'\b(udp|udp6|tcp|tcp6|rdma)\b')
            if re.match(regex, value[1]) is None:
                msg = '"%s" is an invalid "proto" value. ' \
                                 'Valid values are ' \
                                 '(udp|udp6|tcp|tcp6|rdma) ' % value[1]
                return msg

    @staticmethod
    def _option_has_value(value):

        regexp = re.compile(r'\b(timeo|retrans|rsize|wsize|'
                               r'acregmin|acregmax'
                               r'|acdirmin|acdirmax|actimeo|'
                               r'retry|minorversion|port|vers)\b')

        find = re.match(regexp, value[0])

        if find is not None:
            if not value[1].isdigit():
                msg = 'The "%s" option of property "mount_options" requires ' \
                      'a numeric value.' % value[0]
                return msg

    @staticmethod
    def _mount_option_is_valid(value):

        regexp = re.compile(r'\b(sec|lookupcache|clientaddr|timeo|'
                                    r'retrans|rsize|'
                                    r'wsize|ac|noac|acregmin|acregmax'
                                    r'|acdirmin|acdirmax|actimeo|'
                                    r'retry|minorversion|'
                                    r'port|proto|vers)\b')

        find = re.match(regexp, value[0])
        if find is None:
            msg = '"%s" is not valid. ' \
            'Valid mount options are ' \
            '(sec|lookupcache|clientaddr|timeo|actimeo|' \
            'retrans|rsize|wsize|ac|noac|acregmin|acregmax' \
            '|acdirmin|acdirmax|retry|minorversion|' \
            'port|proto|vers). ' % value[0]
            return msg

    @staticmethod
    def _timeo_option_is_valid(value, property_value):
        if "timeo" in value and "actimeo" not in value:
            if "soft" not in property_value:
                msg = 'Unable to use the "timeo" option without ' \
                      'the "soft" option in property "mount_options".'
                return msg

    @staticmethod
    def _contrast_mount_options(property_value):
        """Only one option should be chosen from each of the following pairs
        ('soft', 'hard'), ('ac', 'noac'), ('bg', 'fg'),
        ('sharecache', 'nosharecache'), ('resvport', 'noresvport'),
        ('intr', 'nointr'), ('lock', 'nolock'), ('cto', 'nocto').
        """
        options = property_value.split(',')
        choices = [("soft", "hard"), ("ac", "noac"),
            ("bg", "fg"), ("sharecache", "nosharecache"),
            ("resvport", "noresvport"), ("intr", "nointr"),
            ("lock", "nolock"), ("cto", "nocto"), ]
        base_msg = 'Conflicting nfs mount options input'
        return conflicting_options(choices, options, base_msg)


class NasTypeValidator(PropertyValidator, DebuggerMixin):

    """
    Custom PropertyValidator for the 'nas_type'
    property, which is a property of the 'sfs-service'
    item type. Ensures the property is matches veritas or unityxt
    """

    def validate(self, property_value):

        preamble = 'NasTypeValidator '

        error_msg = 'Only "veritas" or "unityxt" allowed'

        if property_value is not None and \
            property_value.lower() != "veritas" and \
            property_value.lower() != "unityxt":
            self._debug(preamble, error_msg)
            return ValidationError(
                property_name="nas_type",
                error_message=error_msg
            )


class PortsTypeValidator(PropertyValidator, DebuggerMixin):

    """
    Custom PropertyValidator for the 'ports'
    property, which is a property of the 'sfs-virtual_server'
    item type. Ensures the property contains two unique values in '0,1,2,3'
    """

    def validate(self, property_value):

        preamble = 'PortsTypeValidator '
        error_msg = 'Only two unique values in "0,1,2,3" allowed'
        valid_ports = ['0', '1', '2', '3']

        ports = property_value.split(",")

        if len(ports) != 2 or len(ports) > len(set(ports)) or not (
            all(x in valid_ports for x in ports)):
            self._debug(preamble, error_msg)
            return ValidationError(
                property_name="ports",
                error_message=error_msg
            )


class SharingProtocolsTypeValidator(PropertyValidator, DebuggerMixin):

    """
    Custom PropertyValidator for the 'sharing_protocols'
    property, which is a property of the 'sfs-virtual_server'
    item type. Ensures the property matches nfsv3 and/or nfsv4
    """

    def validate(self, property_value):

        preamble = 'SharingProtocolsTypeValidator '

        error_msg = 'Only "nfsv3", "nfsv4" or "nfsv3,nfsv4" allowed'

        if property_value is not None and \
            property_value != "nfsv3" and \
            property_value != "nfsv4" and \
            property_value != "nfsv3,nfsv4":
            self._debug(preamble, error_msg)
            return ValidationError(
                property_name="sharing_protocols",
                error_message=error_msg
            )


class StorageProcessorTypeValidator(PropertyValidator, DebuggerMixin):

    """
    Custom PropertyValidator for the 'sp'
    property, which is a property of the 'sfs-virtual_server'
    item type. Ensures the property is matches spa or spb
    """

    def validate(self, property_value):

        preamble = 'StorageProcessorTypeValidator '

        error_msg = 'Only "spa" or "spb" allowed'

        if property_value is not None and \
            property_value.lower() != "spa" and \
            property_value.lower() != "spb":
            self._debug(preamble, error_msg)
            return ValidationError(
                property_name="sp",
                error_message=error_msg
            )


class GatewayTypeValidator(PropertyValidator, DebuggerMixin):
    """

        If validating a property of type ipv4_address \
        (version set to 4) then \
        the value must be a valid IPv4 address.
        """

    def __init__(self, version="4"):
        """Check property is a valid IP Address

        :param version: IP version to check for ("4", "6" or "both"). \
                        Default is 4
        :type  version: str

        """
        super(GatewayTypeValidator, self).__init__()
        self.version = version

    def validate(self, property_value):
        try:
            if (str(self.version) == '4' \
                and not netaddr.valid_ipv4(property_value,
                                           netaddr.INET_PTON)) or \
                    (str(self.version) == '6' and \
                     not netaddr.valid_ipv6(property_value)):
                raise netaddr.AddrFormatError
        except (netaddr.AddrFormatError, ValueError):
            version_text = "IPv6Address" if str(self.version) == '6' \
                else "IPAddress"
            return ValidationError(
                error_message="Invalid %s value '%s'"
                              % (version_text, str(property_value)))


class SubnetTypeValidator(PropertyValidator):
    """
    Validates that the value of the property is a valid IPv4 network.
    """
    def validate(self, property_value):
        try:
            netaddr.IPNetwork(property_value, version=4)
        except netaddr.AddrFormatError as e:
            if e.args[0] == 'invalid prefix for IPv4 address!':
                error_message = ('Invalid prefix for destination IPv4 network '
                                 'at \'{0}\''.format(property_value))
            else:
                error_message = "Invalid IPv4 subnet value '%s'" % (
                        str(property_value))
            return ValidationError(error_message=error_message)
        except ValueError as e:
            error_message = "Invalid IPv4 subnet value '%s'" % (
                    str(property_value))
            return ValidationError(error_message=error_message)
        except Exception as e:
            return ValidationError(
                error_message="Invalid value: %s" % str(e))

        if not '/' in property_value:
            return ValidationError(
                error_message="Subnet must include prefix length"
            )
