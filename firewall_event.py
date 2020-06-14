import sys
import os
import json
import requests
import hvac
import datetime

SLACK_CHANNEL = os.getenv('SLACK_CHANNEL')


def firewall_report():

    client = hvac.Client(
    url=os.getenv('VAULT_URL'),
    token=os.getenv('VAULT_TOKEN')
)
    if os.getenv('VAULT_TOKEN') is None:
        client.auth.github.login(os.getenv('VAULT_GITHUB_TOKEN'))
    secrets = client.read('infra/security')
    USER = secrets['data']['USER']
    TOKEN = secrets['data']['TOKEN']
    ORGID = secrets['data']['ORGID']
    BASE_URI = "https://api.cloudflare.com/client/v4/"
    current = datetime.datetime.utcnow()
    currenttime = current.strftime('%Y-%m-%dT%H:%M:%S')
    last24  = datetime.datetime.utcnow() - datetime.timedelta(seconds=86400)
    last24hourstime = last24.strftime('%Y-%m-%dT%H:%M:%S')
    headers = {
    'X-Auth-Email': USER,
    'X-Auth-Key': TOKEN,
    'Content-Type': 'application/json',
    }
    ZONE_ID = "779**************a6"

    query2 = """
    {{
    viewer {{
        zones(filter: {{ zoneTag: "779****************a6" }}) {{
        firewallEventsAdaptiveGroups(
            limit: 100
            filter: {{ datetime_gt: "{0}Z", datetime_lt: "{1}Z"}}
        ) {{
            dimensions {{
                action
            }}
            count
        }}
        }}
    }}
    }}""".format(last24hourstime, currenttime)


    request = requests.post('https://api.cloudflare.com/client/v4/graphql', json={'query': query2}, headers=headers)
    print request.json()
    blocked = request.json()['data']['viewer']['zones'][0]['firewallEventsAdaptiveGroups'][2]['count']
    challenge = request.json()['data']['viewer']['zones'][0]['firewallEventsAdaptiveGroups'][4]['count']
    jschallenge = request.json()['data']['viewer']['zones'][0]['firewallEventsAdaptiveGroups'][8]['count']

    print blocked,challenge,jschallenge
    post_to_slack("*Number of requests blocked  :*", SLACK_CHANNEL)
    post_to_slack(blocked, SLACK_CHANNEL)
    post_to_slack("*Number of requests challenged: *", SLACK_CHANNEL)
    post_to_slack(challenge, SLACK_CHANNEL)
    post_to_slack("*Number of requests jschallenged: *", SLACK_CHANNEL)
    post_to_slack(jschallenge, SLACK_CHANNEL)

if __name__ == "__main__":
    firewall_report()
