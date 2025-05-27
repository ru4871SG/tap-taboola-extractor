#!/usr/bin/env python3

from decimal import Decimal

import argparse
import copy
import datetime
import json
import os
import sys
import time
import logging
import pickle

import dateutil.parser

import singer
from singer import utils
import requests

import backoff

import tap_taboola.schemas as schemas

LOGGER = singer.get_logger()

BASE_URL = 'https://backstage.taboola.com'


@backoff.on_exception(backoff.expo,
                      (requests.exceptions.RequestException),
                      max_tries=5,
                      giveup=lambda e: e.response is not None and 400 <= e.response.status_code < 500, # pylint: disable=line-too-long
                      factor=2)
def request(url, access_token, params={}):
    LOGGER.info("Making request: GET {} {}".format(url, params))

    try:
        response = requests.get(
            url,
            headers={'Authorization': 'Bearer {}'.format(access_token),
                     'Accept': 'application/json'},
            params=params)
    except Exception as exception:
        LOGGER.exception(exception)

    LOGGER.info("Got response code: {}".format(response.status_code))

    response.raise_for_status()
    return response

# def get_token_password_auth(client_id, client_secret, username, password):
#     url = '{}/backstage/oauth/token'.format(BASE_URL)
#     params = {
#         'client_id': client_id,
#         'client_secret': client_secret,
#         'username': username,
#         'password': password,
#         'grant_type': 'password',
#     }

#     response = requests.post(
#         url,
#         headers={'Content-Type': 'application/x-www-form-urlencoded',
#                  'Accept': 'application/json'},
#         params=params)

#     LOGGER.info("Got response code: {}".format(response.status_code))

#     result = {}
#     if response.status_code == 200:
#         LOGGER.info("Got an access token.")
#         result = {"token": response.json().get('access_token', None)}
#     elif response.status_code >= 400 and response.status_code < 500:
#         result = {k: response.json().get(k) for k in ('error','error_description')}

#     return result

def get_token_client_credentials_auth(client_id, client_secret):
    url = '{}/backstage/oauth/token'.format(BASE_URL)
    params = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'client_credentials'
    }

    response = requests.post(
        url,
        headers={'Content-Type': 'application/x-www-form-urlencoded',
                 'Accept': 'application/json'},
        params=params)

    LOGGER.info("Got response code: {}".format(response.status_code))

    result = {}
    if response.status_code == 200:
        LOGGER.info("Got an access token.")
        result = {"token": response.json().get('access_token', None)}
    elif response.status_code >= 400 and response.status_code < 500:
        result = {k: response.json().get(k) for k in ('error','error_description')}

    return result


# def generate_token(client_id, client_secret, username, password):
#     LOGGER.info("Generating new token with password auth")
#     token_result = get_token_password_auth(client_id, client_secret, username, password)
#     if 'token' not in token_result:
#         LOGGER.info("Retrying with client credentials authentication.")
#         token_result = get_token_client_credentials_auth(client_id, client_secret)

#     token = token_result.get('token')
#     if token is None:
#         raise Exception('Unable to authenticate, response from Taboola - {}: {}'
#                         .format(token_result.get('error'),
#                                 token_result.get('error_description')))

#     return token

def load_taboola_token(client_id, client_secret):
    """
    Load a cached client-credentials token from disk if valid, otherwise fetch a new one and cache it.
    """
    token_file = f"taboolatoken_{client_id}.pckl"
    try:
        with open(token_file, 'rb') as f:
            token_data = pickle.load(f)
        access_token = token_data.get('access_token')
        # verify it's still good:
        resp = requests.get(
            f"{BASE_URL}/backstage/api/1.0/users/current/account",
            headers={"authorization": f"Bearer {access_token}"}
        )
        if resp.status_code == 200:
            return access_token
    except Exception:
        pass

    # fetch new client-credentials token
    token_data = get_token_client_credentials_auth(client_id, client_secret)
    if "token" not in token_data:
        raise RuntimeError(f"Auth failed: {token_data.get('error_description')}")
    with open(token_file, 'wb') as f:
        pickle.dump({"access_token": token_data["token"]}, f)
    return token_data["token"]


def get_network_id(access_token):
    """
    Return the “master” network account_id for the token.
    """
    url = f"{BASE_URL}/backstage/api/1.0/users/current/account"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    )
    resp.raise_for_status()
    return resp.json()["account_id"]


def get_account_ids(network_id, access_token):
    """
    List all sub-account IDs under a given network.
    """
    url = f"{BASE_URL}/backstage/api/1.0/{network_id}/advertisers"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    )
    resp.raise_for_status()
    return [adv["account_id"] for adv in resp.json().get("results", [])]


def parse_campaign_performance(campaign_performance):
    raw_date = campaign_performance.get('date', '')
    date = raw_date.split()[0] if ' ' in raw_date else raw_date

    return {
        'date': date,
        'spend': float(campaign_performance.get('spent', 0.0)),
        'clicks': int(campaign_performance.get('clicks', 0)),
        'impressions': int(campaign_performance.get('impressions', 0)),
        'conversions_value': float(campaign_performance.get('conversions_value', 0.0)),
        'roas': float(campaign_performance.get('roas', 0.0)),
        'roas_clicks': float(campaign_performance.get('roas_clicks', 0.0)),
        'roas_views': float(campaign_performance.get('roas_views', 0.0)),
        'ctr': float(campaign_performance.get('ctr', 0.0)),
        'vctr': float(campaign_performance.get('vctr', 0.0)),
        'cpm': float(campaign_performance.get('cpm', 0.0)),
        'vcpm': float(campaign_performance.get('vcpm', 0.0)),
        'cpc': float(campaign_performance.get('cpc', 0.0)),
        'cpa': float(campaign_performance.get('cpa', 0.0)),
        'cpa_clicks': float(campaign_performance.get('cpa_clicks', 0.0)),
        'cpa_views': float(campaign_performance.get('cpa_views', 0.0)),
        'cpa_actions_num': int(campaign_performance.get('cpa_actions_num', 0)),
        'cpa_actions_num_from_clicks': int(campaign_performance.get('cpa_actions_num_from_clicks', 0)),
        'cpa_actions_num_from_views': int(campaign_performance.get('cpa_actions_num_from_views', 0)),
        'cpa_conversion_rate': float(campaign_performance.get('cpa_conversion_rate', 0.0)),
        'cpa_conversion_rate_clicks': float(campaign_performance.get('cpa_conversion_rate_clicks', 0.0)),
        'cpa_conversion_rate_views': float(campaign_performance.get('cpa_conversion_rate_views', 0.0)),
        'currency': campaign_performance.get('currency', '')
    }

def fetch_campaign_performance(config, state, access_token, account_id):
    url = (
        f"{BASE_URL}/backstage/api/1.0/{account_id}"
        "/reports/campaign-summary/dimensions/day"
    )
    params = {
        'start_date': config['start_date'],
        'end_date':   config['end_date'],
    }

    response = request(url, access_token, params)
    return response.json().get('results', [])


def sync_campaign_performance(config, state, access_token, account_id, network_id):
    performance = fetch_campaign_performance(config, state, access_token,
                                             account_id)

    time_extracted = utils.now()

    LOGGER.info("Got {} campaign performance records."
                .format(len(performance)))

    for record in performance:
        parsed = parse_campaign_performance(record)
        parsed['account_id'] = account_id
        parsed['network_id'] = network_id
        singer.write_record(
            'campaign_performance',
            parsed,
            time_extracted=utils.now()
        )

    LOGGER.info("Done syncing campaign_performance.")


def parse_campaign(campaign):
    start_date = campaign.get('start_date')
    end_date = campaign.get('end_date')

    return {
        'id': int(campaign.get('id')),
        'advertiser_id': str(campaign.get('advertiser_id', '')),
        'name': str(campaign.get('name', '')),
        'tracking_code': str(campaign.get('tracking_code', '')),
        'cpc': float(campaign.get('cpc') or 0.0),
        'daily_cap': float(campaign.get('daily_cap') or 0.0),
        'spending_limit': float(campaign.get('spending_limit') or 0.0),
        'spending_limit_model': str(campaign.get('spending_limit_model', '')),
        'country_targeting': campaign.get('country_targeting'),
        'platform_targeting': campaign.get('platform_targeting'),
        'publisher_targeting': campaign.get('publisher_targeting'),
        'start_date': str('9999-12-31' if start_date is None else start_date),
        'end_date': str('9999-12-31' if end_date is None else end_date),
        'approval_state': str(campaign.get('approval_state', '')),
        'is_active': bool(campaign.get('is_active', False)),
        'spent': float(campaign.get('spent') or 0.0),
        'status': str(campaign.get('status', '')),
    }

def fetch_campaigns(access_token, account_id):
    url = '{}/backstage/api/1.0/{}/campaigns/'.format(BASE_URL, account_id)

    response = request(url, access_token)
    return response.json().get('results')


def sync_campaigns(access_token, account_id):
    campaigns = fetch_campaigns(access_token, account_id)
    time_extracted = utils.now()

    LOGGER.info('Synced {} campaigns.'.format(len(campaigns)))

    for record in campaigns:
        parsed_campaigns = parse_campaign(record)

        singer.write_record('campaigns',
                            parsed_campaigns,
                            time_extracted=time_extracted)

    LOGGER.info("Done syncing campaigns.")


def verify_account_access(access_token, account_id):
    url = '{}/backstage/api/1.0/token-details/'.format(BASE_URL)
    result = request(url, access_token)
    
    token_account_id = result.json().get('account_id')
    if token_account_id != account_id:
        LOGGER.warn(("Token issued for network account '{}', using specified sub-account '{}'")
                   .format(token_account_id, account_id))
        return account_id  # Return original account_id instead of token's account_id

    LOGGER.info("Verified account access via token details endpoint.")
    return account_id


def fetch_sub_accounts(access_token, account_id):
    url = f'{BASE_URL}/backstage/api/1.0/{account_id}/advertisers'
    try:
        response = request(url, access_token)
        sub_accounts = [adv["account_id"] for adv in response.json().get("results", [])]
        # If no sub-accounts, treat the input account_id as the only account
        return sub_accounts if sub_accounts else [account_id]
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            # If it's a non-network account, sync the input account
            LOGGER.info(f"Account {account_id} is not a network account, syncing directly")
            return [account_id]
        else:
            raise


# def validate_config(config):
#     missing = []
#     if 'credentials' not in config or not isinstance(config['credentials'], list):
#         missing.append('credentials')
#     if 'start_date' not in config:
#         missing.append('start_date')
#     if missing:
#         LOGGER.fatal(f"Config missing: {', '.join(missing)}")
#         raise RuntimeError("Invalid config")
#     missing_keys = []
#     null_keys = []
#     has_errors = False

#     for required_key in required_keys:
#         if required_key not in config:
#             missing_keys.append(required_key)

#         elif config.get(required_key) is None:
#             null_keys.append(required_key)

#     if missing_keys:
#         LOGGER.fatal("Config is missing keys: {}"
#                      .format(", ".join(missing_keys)))
#         has_errors = True

#     if null_keys:
#         LOGGER.fatal("Config has null keys: {}"
#                      .format(", ".join(null_keys)))
#         has_errors = True

#     if has_errors:
#         raise RuntimeError


def validate_config(config):
    missing = []
    if not isinstance(config.get('credentials'), list) or not config['credentials']:
        missing.append('credentials')
    if 'start_date' not in config:
        missing.append('start_date')
    if missing:
        LOGGER.fatal(f"Config missing required keys: {', '.join(missing)}")
        raise RuntimeError("Invalid tap configuration")


def load_config(filename):
    config = {}

    try:
        with open(filename) as config_file:
            config = json.load(config_file)
    except:
        LOGGER.fatal("Failed to decode config file. Is it valid json?")
        raise RuntimeError

    validate_config(config)

    return config


def load_state(filename):
    if filename is None:
        return {}

    try:
        with open(filename) as state_file:
            return json.load(state_file)
    except:
        LOGGER.fatal("Failed to decode state file. Is it valid json?")
        raise RuntimeError


# def do_sync(args):
#     LOGGER.info("Starting sync.")

#     config = load_config(args.config)
#     state = load_state(args.state)

#     access_token = generate_token(
#         client_id=config.get('client_id'),
#         client_secret=config.get('client_secret'),
#         username=config.get('username'),
#         password=config.get('password'))

#     singer.write_schema('campaigns',
#                         schemas.campaign,
#                         key_properties=['id'])

#     singer.write_schema('campaign_performance',
#                         schemas.campaign_performance,
#                         key_properties=['campaign_id', 'date'])

#     # config['account_id'] = verify_account_access(access_token, config.get('account_id'))

#     sync_campaigns(access_token, config.get('account_id'))
#     sync_campaign_performance(config, state, access_token,
#                               config.get('account_id'))
    

def do_sync(args):
    LOGGER.info("Starting sync.")

    config = load_config(args.config)
    state = load_state(args.state)

    # Write schemas once
    singer.write_schema('campaigns', schemas.campaign, key_properties=['id'])
    singer.write_schema(
        'campaign_performance',
        schemas.campaign_performance,
        key_properties=['network_id','account_id','date']
    )
    
    # For each credential pair…
    for creds in config['credentials']:
        token = load_taboola_token(creds['client_id'], creds['client_secret'])
        network_id = get_network_id(token)
        try:
            # For network credentials, list the child advertisers
            sub_accounts = get_account_ids(network_id, token)
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                # for advertiser levels, use its own account_id
                sub_accounts = [network_id]
            else:
                raise

        # …sync _each_ sub-account under that network
        for account_id in sub_accounts:
            LOGGER.info(f"Syncing {network_id} → {account_id}")
            sync_campaigns(token, account_id)
            sync_campaign_performance(
                config,
                state,
                access_token=token,
                account_id=account_id,
                network_id=network_id,
            )


def main_impl():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-c', '--config', help='Config file', required=True)
    parser.add_argument(
        '-s', '--state', help='State file')

    args = parser.parse_args()

    try:
        do_sync(args)
    except RuntimeError:
        LOGGER.fatal("Run failed.")
        exit(1)

def main():
    try:
        main_impl()
    except Exception as exc:
        LOGGER.critical(exc)
        raise exc

if __name__ == '__main__':
    main()
