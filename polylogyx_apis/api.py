#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Simple class to interact with Polylogyx's Api.
:copyright: (c) 2019 by PolyLogyx.
:license: MIT, see LICENSE for more details.
The APIs are documented at:
https://github.com/polylogyx/polylogyx-api/
EXAMPLE USAGE:::
from api import PolylogyxApi
polylogyxApi = PolylogyxApi(domain=<IP/DOMAIN>, username=<USERNAME>,
                                         password=<PASSWORD>)
response = polylogyxApi.get_nodes()
print json.dumps(response, sort_keys=False, indent=4)
"""
import requests
from websocket import create_connection
import ssl
import uuid
import random
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import stix2

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TIMEOUT_SECS = 30


def get_deterministic_uuid(prefix=None, seed=None):
    if seed is None:
        stix_id = uuid.uuid4()
    else:
        random.seed(seed)
        a = "%32x" % random.getrandbits(128)
        rd = a[:12] + '4' + a[13:16] + 'a' + a[17:]
        stix_id = uuid.UUID(rd)

    return "{}{}".format(prefix, stix_id)


def generate_mitre_lookup():
    r = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')

    if r.status_code != requests.codes.ok:
        print('Failed to get Mitre Att&ck data')
        return False

    out = {}
    pattern = re.compile(r'TA\d{4}|[T|S|G|M]\d{4}')
    for obj in r.json()['objects']:
        if 'external_references' not in obj:
            continue
        if 'kill_chain_phases' not in obj:
            continue
        for ref in obj['external_references']:
            if 'external_id' not in ref:
                continue
            if pattern.search(ref['external_id']):
                mitre_id = ref['external_id']
                break
        for phase in obj['kill_chain_phases']:
            if phase['kill_chain_name'] != 'mitre-attack':
                continue
            phase_name = phase['phase_name']
            break
        try:
            out[phase_name].append((mitre_id, obj['id']))
        except KeyError:
            out[phase_name] = [(mitre_id, obj['id'])]
    return out


MITRE_LOOKUP = generate_mitre_lookup()


# Given either a stix_id or mitre_id, returns the phase name and the other id.
def get_phase(mitre_id):
    for phase in MITRE_LOOKUP:
        for entry in MITRE_LOOKUP[phase]:
            if entry[0] == mitre_id:
                return phase, entry[1]
            elif entry[1] == mitre_id:
                return phase, entry[0]
    return False


class PolylogyxApi:

    def __init__(self, domain=None, username=None, password=None):
        self.username = username
        self.password = password
        self.version = 0
        self.max_retries = 5
        self.domain = domain
        self.base = "https://" + domain + ":5000/services/api/v0"

        if username is None or password is None:
            raise ApiError("You must supply a username and password.")
        if self.fetch_token():
            raise ApiError("Connection failed: Check server availability.")

    def fetch_token(self):
        url = self.base + '/login'
        payload = {'username': self.username, 'password': self.password}
        try:
            response = _return_response_and_status_code(requests.post(
                url, json=payload, headers={},
                verify=False, timeout=TIMEOUT_SECS))
            if response['response_code'] == 200:
                self.AUTH_TOKEN = response['results']['token']
            elif response['response_code'] == 401:
                raise ApiError("Invalid username and or  password.")
        except requests.RequestException as e:
            return dict(error=str(e))

    def get_nodes(self):
        """ This API allows you to get all the nodes registered.
            :return: JSON response that contains list of nodes.
        """

        url = self.base + "/nodes/"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def get_alerts(self, data):
        """ This API allows you to get all the nodes registered.
            :return: JSON response that contains list of nodes.
        """

        url = self.base + "/alerts"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.post(
                url, headers=headers, json=data,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def send_distributed_query(self, sql=None, tags=[], host_identifiers=[]):
        """ Send a query to nodes.
               This API allows you to execute an on-demand query on the nodes.
               :param sql: The sql query to be executed
               :param tags: Specify the array of tags.
               :param host_identifiers: Specify the host_identifier array.
               :return: JSON response that contains query_id.
               """
        payload = {
            "query": sql,
            "nodes": host_identifiers,
            "tags": tags
        }

        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + "/distributed/add"
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_distributed_query_results(self, query_id):

        """ Retrieve the query results based on the query_id query.
               This API uses websocket connection for getting data.
               :param query_id: Query id for which the results to be fetched
               :return: Stream data of a query executed on nodes.
        """
        conn = create_connection("wss://" + self.domain + ":5000" + "/distributed/result",
                                 sslopt={"cert_reqs": ssl.CERT_NONE})

        conn.send(str(query_id))
        result = conn.recv()
        return conn

    def get_query_data(self, query_name=None, host_identifier=None, start=1, limit=100):

        payload = {'host_identifier': host_identifier, 'query_name': query_name, 'start': start, 'limit': limit}
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + '/nodes/schedule_query/results'
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_query_results(self, days_of_data=1):
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = '{}/queryresult/{}'.format(self.base, days_of_data)
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_alert_data(self, alert_id=None):
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = '{}/alerts/data/{}'.format(self.base, alert_id)
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_rules(self, rule_id=None):
        if not rule_id:
            rule_id = ''
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = '{}/rules/{}'.format(self.base, rule_id)
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def search_query_data(self, search_conditions):

        payload = search_conditions
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + "/search"
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_carves(self, host_identifier=None):
        """ Retrieve file carving  list.
               This API allows you to execute an on-demand query on the nodes.
               :param host_identifier: Node host_identifier for which the carves to fetched.
               :return: JSON response that contains list of file carving done.
        """
        payload = {'host_identifier': host_identifier}
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + "/carves/"

        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_carve_by_query_id(self, query_id=None, host_identifier=None):
        """ Download the carved file using the sesion_id.
               This API allows you to execute an on-demand query on the nodes.
               :param session_id: session id of a carve to be downloaded.
               :return: File content.
        """
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                self.base + "/carves/query/" + str(query_id) + "/" + host_identifier, headers=headers, verify=False)

        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def download_carve(self, session_id=None):
        """ Download the carved file using the sesion_id.
               This API allows you to execute an on-demand query on the nodes.
               :param session_id: session id of a carve to be downloaded.
               :return: File content.
        """
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                self.base + "/carves/download/" + session_id, headers=headers, verify=False)
            return response.content
        except requests.RequestException as e:
            return dict(error=str(e))

    def take_action(self, data):
        """ This API allows you to get all the nodes registered.
            :return: JSON response that contains list of nodes.
        """

        url = self.base + "/response/add"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.post(
                url, headers=headers, json=data,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def get_action_status(self, command_id):
        """ This API allows you to get all the nodes registered.
            :return: JSON response that contains list of nodes.
        """

        url = self.base + "/response/" + command_id
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def add_query(self, query, tags=None):
        """ This API allows you to add a query to the server.
            :param query: PLGX format query as dict.
            :param tags: If the base query is osquery, optionally add plgx tags
            :return: JSON response containing status, message and query id.
        """

        if tags:
            try:
                query['tags'] += ','.join(tags)
            except KeyError:
                query['tags'] = ','.join(tags)

        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + "/queries/add"
        try:
            response = requests.post(
                url, json=query, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def add_pack(self, pack):
        """ This API allows you to add a pack to the server.
            :param query: PLGX format pack as dict.
            :return: JSON response containing status, message and query id.
        """

        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + "/packs/add"
        try:
            response = requests.post(
                url, json=pack, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def add_rule(self, rule):
        """ This API allows you to add a rule to the server.
            :param rule: PLGX format rule as dict.
            :return: JSON response containing status, message and query id.
        """

        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = self.base + "/rules/add"
        try:
            response = requests.post(
                url, json=rule, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def deploy_technique_pack(self, pack, mitre_id, tags, alerters):
        """ Provide an osquery 'pack' to the server along with an appropriate rule
            that will deploy the constituent rules to the nodes.
            :param pack: OSQuery pack (with multiple queries) as dict.
            :param mitre_id: Mitre id for the technique being deployed.
            :param tags: List of PLGX tags to apply to rule to trigger deployment.
            :param alerters: List of PLGX alerters to apply to rule.
            :return: JSON response containing statuses for deployed packs and rules.
        """
        if 'queries' not in pack:
            print('Pack must contain `queries`.')
            return False
        phase_name, stix_id = get_phase(mitre_id)
        pack_rules = []
        for query in pack['queries']:
            pack_rules.append({
                'id': 'query_name',
                'type': 'string',
                'field': 'query_name',
                'input': 'text',
                'value': query,
                'operator': 'equal'
            })
        technique_rule = {
                'alerters': ','.join(alerters),
                'conditions': {'rules': pack_rules,
                               'condition': 'OR'},
                'name': stix_id,
                'status': 'ACTIVE',
                'type': 'MITRE',
                'tactics': [phase_name],
                'technique_id': mitre_id,
                'description': pack['description'],
        }
        # Add tags which is the way to tell plgx server to deploy to nodes
        #  that also have that tag.
        try:
            pack['tags'] += ','.join(tags)
        except KeyError:
            pack['tags'] = ','.join(tags)
        # Also add a name (required by plgx)
        pack['name'] = mitre_id
        return {'pack': self.add_pack(pack),
                'rule': self.add_rule(technique_rule)}

    def deploy_threat_packs(self, packs, threat_name, tags, alerters):
        """ Provide a set of packs with related mitre_ids that, together,
            constitute a threat. A threat can be any top-level intelligence
            concept such as a threat actor, malware family name or similar.
            The threat itself is represented by a rule that makes use of the
            deployed technique packs.
            :param packs: Dict of mitre_id keys and related OSQuery pack values.
            :param threat_name: Name of the threat concept - ideally a Mitre stix_id.
            :param tags: List of PLGX tags to apply to rule to trigger deployment.
            :param alerters: List of PLGX alerters to apply to rule.
            :return: JSON response containing status and message.
        """

        threat_rules = []
        result = {'pack': [],
                  'rule': []}
        for mitre_id in packs:
            pack_res = self.deploy_technique_pack(
                            pack=packs[mitre_id],
                            mitre_id=mitre_id,
                            tags=tags,
                            alerters=alerters)
            result['pack'].append(pack_res['pack'])
            result['rule'].append(pack_res['rule'])
            for query in packs[mitre_id]['queries']:
                threat_rules.append({
                    'id': 'query_name',
                    'type': 'string',
                    'field': 'query_name',
                    'input': 'text',
                    'value': query,
                    'operator': 'equal'
                })
        threat_rule = {
                'alerters': ','.join(alerters),
                'conditions': {'rules': threat_rules,
                               'condition': 'AND'},
                'name': threat_name,
                'status': 'ACTIVE',
                'type': 'MITRE',
                # 'tactics': [phase_name],
                # 'technique_id': mitre_id,
                'description': packs[mitre_id]['description'],
        }
        result['rule'].append(self.add_rule(threat_rule))
        return result

    def get_stix_sightings(self, rule_id):
        data = {'rule_id': rule_id}
        alerts = self.get_alerts(data=data)
        if alerts['results']['status'] != 'success':
            return []

        sightings = []
        bundle = stix2.Bundle(objects=sightings)

        return bundle


class ApiError(Exception):
    pass


def _return_response_and_status_code(response, json_results=True):
    """ Output the requests response content or content as json and status code

    :rtype : dict
    :param response: requests response object
    :param json_results: Should return JSON or raw content
    :return: dict containing the response content and/or the status code with error string.
    """
    if response.status_code == requests.codes.ok:
        return dict(results=response.json() if json_results else response.content, response_code=response.status_code)
    elif response.status_code == 400:
        return dict(
            error='package sent is malformed.',
            response_code=response.status_code)
    elif response.status_code == 404:
        return dict(error='Requested URL not found.', response_code=response.status_code)

    else:
        return dict(response_code=response.status_code)
