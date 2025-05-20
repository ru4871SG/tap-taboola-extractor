#pylint: disable=invalid-name
campaign = {
    'type': 'object',
    'properties': {
        'id': {
            'type': 'integer',
            'description': 'The ID of this campaign',
        },
        'advertiser_id': {
            'type': 'string',
            'description': 'i.e. taboola-demo-advertiser',
        },
        'name': {
            'type': 'string',
            'description': 'i.e. Demo Campaign',
        },
        'tracking_code': {
            'type': 'string',
            'description': 'i.e. taboola-track',
        },
        'cpc': {
            'type': 'number',
            'description': 'Cost per click for the whole campaign, i.e. 0.25',
        },
        'daily_cap': {
            'type': 'number',
            'description': 'i.e. 100',
        },
        'spending_limit': {
            'type': 'number',
            'description': 'i.e. 1000',
        },
        'spending_limit_model': {
            'type': 'string',
            'description': 'i.e. "MONTHLY"',
        },
        'country_targeting': {
            'type': ['object', 'null'],
            'description': (
                'Country codes to target. '
                'Type is like "INCLUDE", value is like ["AU","GB"]'
            ),
            'properties': {
                'type': {'type': 'string'},
                'value': {
                    'type': 'array',
                    'items': {'type': 'string'}
                }
            }
        },
        'platform_targeting': {
            'type': ['object', 'null'],
            'description': (
                'Platforms to target. '
                'Type is like "INCLUDE", value is like ["TBLT","PHON"]'
            ),
            'properties': {
                'type': {'type': 'string'},
                'value': {
                    'type': 'array',
                    'items': {'type': 'string'}
                }
            }
        },
        'publisher_targeting': {
            'type': ['object', 'null'],
            'description': 'Publishers to target.',
            'properties': {
                'type': {'type': 'string'},
                'value': {
                    'type': 'array',
                    'items': {'type': 'string'}
                }
            }
        },
        'start_date': {
            'type': 'string',
            'format': 'date',
            'description': 'The start date for this campaign.',
        },
        'end_date': {
            'type': 'string',
            'format': 'date',
            'description': 'The end date for this campaign.',
        },
        'approval_state': {
            'type': 'string',
            'description': 'Approval state for the campaign, i.e. "APPROVED".'
        },
        'is_active': {
            'type': 'boolean',
            'description': 'Whether or not the campaign is active.',
        },
        'spent': {
            'type': 'number',
            'description': 'Total amount spent by this campaign.',
        },
        'status': {
            'type': 'string',
            'description': 'i.e. "RUNNING"',
        }
    }
}

campaign_performance = {
    'type': 'object',
    'properties': {
        'network_id': {
            'type': 'string',
            'description': 'Taboola network (parent) account ID',
        },
        'account_id': {
            'type': 'string',
            'description': 'Taboola advertiser (sub-account) ID',
        },
        'date': {
            'type': 'string',
            'format': 'date',
            'description': 'The date for this summary record.',
        },
        'spend': {
            'type': 'number',
            'description': 'Total spend on that date for this account.',
        },
        'clicks': {
            'type': 'integer',
            'description': 'Number of clicks on that date.',
        },
        'impressions': {
            'type': 'integer',
            'description': 'Number of impressions on that date.',
        },
        'conversions_value': {
            'type': 'number',
            'description': 'Total value of conversions.',
        },
        'roas': {
            'type': 'number',
            'description': 'Return on ad spend.',
        },
        'roas_clicks': {
            'type': 'number',
            'description': 'ROAS based on clicks.',
        },
        'roas_views': {
            'type': 'number',
            'description': 'ROAS based on views.',
        },
        'ctr': {
            'type': 'number',
            'description': 'Click-through rate.',
        },
        'vctr': {
            'type': 'number',
            'description': 'View-through click rate.',
        },
        'cpm': {
            'type': 'number',
            'description': 'Cost per thousand impressions.',
        },
        'vcpm': {
            'type': 'number',
            'description': 'View CPM.',
        },
        'cpc': {
            'type': 'number',
            'description': 'Cost per click.',
        },
        'cpa': {
            'type': 'number',
            'description': 'Cost per acquisition.',
        },
        'cpa_clicks': {
            'type': 'number',
            'description': 'Cost per acquisition based on clicks.',
        },
        'cpa_views': {
            'type': 'number',
            'description': 'Cost per acquisition based on views.',
        },
        'cpa_actions_num': {
            'type': 'integer',
            'description': 'Number of conversion actions.',
        },
        'cpa_actions_num_from_clicks': {
            'type': 'integer',
            'description': 'Conversion actions from clicks.',
        },
        'cpa_actions_num_from_views': {
            'type': 'integer',
            'description': 'Conversion actions from views.',
        },
        'cpa_conversion_rate': {
            'type': 'number',
            'description': 'Conversion rate.',
        },
        'cpa_conversion_rate_clicks': {
            'type': 'number',
            'description': 'Conversion rate based on clicks.',
        },
        'cpa_conversion_rate_views': {
            'type': 'number',
            'description': 'Conversion rate based on views.',
        },
        'currency': {
            'type': 'string',
            'description': 'Currency code, e.g. "USD".',
        },
    }
}