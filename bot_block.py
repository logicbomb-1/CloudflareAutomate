import sys
import os
import json
import requests
import hvac
import datetime

from common.common import post_to_slack, get_logger

logger = get_logger(__name__, level='DEBUG')
SLACK_CHANNEL = os.getenv('SLACK_CHANNEL')

def bot_block():
    client = hvac.Client(
    url=os.getenv('VAULT_URL'),
    token=os.getenv('VAULT_TOKEN')
    )
    if os.getenv('VAULT_TOKEN') is None:
        client.auth.github.login(os.getenv('VAULT_GITHUB_TOKEN'))
    secrets = client.read('infra/security')
    current = datetime.datetime.utcnow()
    currenttime = current.strftime('%Y-%m-%dT%H:%M:%S')
    last24  = datetime.datetime.utcnow() - datetime.timedelta(seconds=86400)
    last24hourstime = last24.strftime('%Y-%m-%dT%H:%M:%S')
    headers = {
    'X-Auth-Email': USER,
    'X-Auth-Key': TOKEN,
    'Content-Type': 'application/json',
    }
    ZONE_ID = "7************6"
    uri = os.path.join('https://api.cloudflare.com/client/v4/accounts/', ORGID, 'firewall/access_rules/rules')
    query3 = """
    query FirewallEventsByTime($zoneTag: string, $filter: FirewallEventsAdaptiveGroupsFilter_InputObject) {{
    viewer {{
        zones(filter: {{ zoneTag: "7***********6" }}) {{
        topIPS:firewallEventsAdaptiveGroups(
            limit: 15
            filter: {{ datetime_gt: "{0}Z", datetime_lt: "{1}Z",action: "simulate"}}
            orderBy: [count_DESC]
        ) {{
            dimensions {{
                clientIP
            }}
            count
        }}
        }}
    }}
    }}""".format(last24hourstime, currenttime)


    request = requests.post('https://api.cloudflare.com/client/v4/graphql', json={'query': query3}, headers=headers)
    for i in range(15):
        count =  request.json()['data']['viewer']['zones'][0]['topIPS'][i]['count']
        ip =  request.json()['data']['viewer']['zones'][0]['topIPS'][i]['dimensions']['clientIP']
        print("Count:{0}, IP:{1}").format(count,ip)
        if count > 20000:

            data = {
                "mode": "block",
                "configuration": {
                    "target": "ip",
                    "value": ip
            },
            "notes": "high number of requests 20k"
            }
            try:
                response = requests.post(uri, json=data, headers=headers)
                print response.content
            except Exception as e:
                print e

if __name__ == "__main__":
    bot_block()
