"""Original Unlicense. Scoped NSG transaction for the held certificate service."""
import copy
import ipaddress
import re
import time

from https_edge import certificate_ingress_candidate


ETAG = r'(?:W/)?"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"'
PROPERTIES = {'provisioningState', 'resourceGuid', 'securityRules', 'defaultSecurityRules', 'subnets', 'networkInterfaces'}
ARRAYS = ('sourcePortRanges', 'destinationPortRanges', 'sourceAddressPrefixes', 'destinationAddressPrefixes')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def etag(view):
    value = view.get('etag')
    require(isinstance(value, str) and re.fullmatch(ETAG, value), 'The selected NSG has no usable version.')
    return value


def policy(view, resource_id, subnet_id):
    props = view['properties']
    require(view['id'].lower() == resource_id.lower() and not props.get('networkInterfaces')
            and [entry['id'].lower() for entry in props['subnets']] == [subnet_id.lower()]
            and set(props) <= PROPERTIES, 'Selected NSG identity or associations changed.')
    rules = []
    for entry in props['securityRules']:
        fields = {key: value for key, value in entry['properties'].items()
                  if key != 'provisioningState' and not (key in ARRAYS and value == [])}
        rules.append({'name': entry['name'], 'properties': fields})
    return {'location': view['location'], 'tags': copy.deepcopy(view['tags']),
            'properties': {'securityRules': sorted(rules, key=lambda rule: rule['properties']['priority'])}}


def plan(facts, nsg, subnet, nic):
    candidate = certificate_ingress_candidate(facts, nsg, subnet)
    subnet_id = subnet['id']
    props = nic['properties']
    require(nic['id'].lower() == facts['NicId'].lower() and props['provisioningState'] == 'Succeeded'
            and props['virtualMachine']['id'].lower() == facts['VmId'].lower() and len(props['ipConfigurations']) == 1,
            'Selected NIC is no longer the single owned VM NIC.')
    config = props['ipConfigurations'][0]
    values = config['properties']
    require(config['id'].lower() == facts['IpConfigurationId'].lower()
            and values['subnet']['id'].lower() == subnet_id.lower()
            and values['publicIPAddress']['id'].lower() == facts['PublicIpId'].lower(),
            'Selected NIC IP configuration linkage changed.')
    address = ipaddress.IPv4Address(values['privateIPAddress'])
    network = ipaddress.IPv4Network(subnet['properties']['addressPrefix'])
    require(address.is_private and address in network and address not in (network.network_address, network.broadcast_address),
            'The selected NIC does not have a private address in the owned subnet.')
    candidate['body']['properties']['securityRules'][0]['properties']['destinationAddressPrefix'] = str(address)
    return dict(resource_id=candidate['resource_id'], subnet_id=subnet_id, opening_etag=candidate['if_match'],
                original=policy(nsg, candidate['resource_id'], subnet_id), temporary=candidate['body'])


def settled(read, intent, deadline):
    while True:
        view = read(intent['resource_id'])
        state = policy(view, intent['resource_id'], intent['subnet_id'])
        version = etag(view)
        if view['properties']['provisioningState'] == 'Succeeded':
            require(state in (intent['original'], intent['temporary']), 'NSG policy changed outside the certificate trial.')
            return state, version
        require(time.monotonic() < deadline, 'Selected NSG did not settle before the observation deadline.')
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def restore(intent, read, put, *, seconds=45):
    """Restore only an exact trial policy, retaining unrelated changes for review."""
    deadline = time.monotonic() + seconds
    current, version = settled(read, intent, deadline)
    if current == intent['temporary']:
        try:
            put(intent['resource_id'], intent['original'], version)
        except OSError:
            pass  # The one restore submission may have reached ARM.
        while current != intent['original']:
            require(time.monotonic() < deadline, 'The original NSG policy is not confirmed restored.')
            time.sleep(min(2, max(0, deadline - time.monotonic())))
            current, version = settled(read, intent, deadline)
    return version


def run(intent, read, put, probe, record, *, seconds=45):
    """Open once, run the caller's bounded probe, and restore in all normal exits.

    The caller must reserve durable attempt storage and verify the live held-only
    listener and firewall before entering. The transport must bound each call.
    A controller crash needs reconciliation using the saved original and intent.
    """
    deadline = time.monotonic() + seconds
    current, version = settled(read, intent, deadline)
    require(current == intent['original'] and version == intent['opening_etag'], 'NSG changed before the certificate trial.')
    record('ingress-intent', copy.deepcopy(intent))
    status = None
    opened = False
    try:
        status = put(intent['resource_id'], intent['temporary'], version)
        require(status in (200, 201, 202), 'Azure did not confirm the certificate ingress submission.')
        while not opened:
            current, _ = settled(read, intent, deadline)
            opened = current == intent['temporary']
            if not opened:
                require(time.monotonic() < deadline, 'Temporary certificate ingress did not become observable.')
                time.sleep(min(2, max(0, deadline - time.monotonic())))
        return probe()
    finally:
        # An original-looking policy can precede a delayed, unacknowledged
        # opening. Record it without claiming a verified close in that case.
        prior, _ = settled(read, intent, time.monotonic() + seconds)
        restored = restore(intent, read, put, seconds=seconds)
        verified_closed = opened or prior == intent['temporary'] or status == 412
        record('ingress-outcome', dict(original_observed=True, verified_closed=verified_closed,
                                       opening_http_status=status, observed_etag=restored))
        require(verified_closed, 'Opening outcome is uncertain. Reconcile the same NSG without reopening.')
