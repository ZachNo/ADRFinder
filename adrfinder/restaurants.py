import json
import requests
from collections import OrderedDict
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from requests.packages.urllib3.util import ssl_
import ssl


CIPHERS = (
    'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:AES256-SHA'
)


class TlsAdapter(HTTPAdapter):

    def __init__(self, ssl_options=0, **kwargs):
        self.ssl_options = ssl_options
        super(TlsAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, *pool_args, **pool_kwargs):
        ctx = ssl_.create_urllib3_context(ciphers=CIPHERS, cert_reqs=ssl.CERT_REQUIRED, options=self.ssl_options)
        self.poolmanager = PoolManager(*pool_args,
                                       ssl_context=ctx,
                                       **pool_kwargs)


class Restaurants(object):

    def get_dining_data(self):
        """
        Get the dining page for WDW
        """
        if hasattr(self, 'dining_page'):
            return self.dining_page

        request_headers = {}
        request_headers["User-Agent"] = "ADRFinder"
        request_headers["Referer"] = "https://disneyworld.disney.go.com/dining/"

        url_auth = 'https://disneyworld.disney.go.com/finder/api/v1/authz/public'
        url_dining = 'https://disneyworld.disney.go.com/finder/api/v1/explorer-service/list-ancestor-entities/wdw/80007798;entityType=destination/2022-09-02/dining'

        session = requests.Session()
        session.headers.update(request_headers)
        adapter = TlsAdapter(ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
        session.mount("https://", adapter)

        try:
            r = session.post(url_auth)
            r.raise_for_status()
            r = session.get(url_dining)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(">> Request failed: {}".format(e))
            raise SystemExit(e)

        r.encoding = "utf-8"
        json_content = r.text

        dining_page = json.loads(json_content)

        session.close()

        self.dining_page = dining_page
        return self.dining_page

    def get_restaurants(self):
        """
        Find all the restaurants at WDW
        Filter the ones that accept reservations

        return: dict { restaurant_name: restaurant_id;type }

        TODO: Probably is a better way to do this than
        scraping but haven't found an endpoint
        yet that doesn't require looping through every
        restaurant (300+ API hits)
        """

        dining_page = self.get_dining_data()

        ###
        # Parse out restaurant ID to name correlation
        ###
        restaurant_info = {}

        for entity in dining_page['results']:
            for facet, value in entity['facets'].items():
                if "reservations-accepted" in value:
                    restaurant_info[entity['id']] = entity['name']
                    break

        return restaurant_info

    def get_search_times(self):
        """
        Get the valid search times => values from disney dining page
        """

        # dining_page = self.get_dining_data()

        search_info = OrderedDict()
        # search_data = dining_page.find('span', {"id": 'searchTime-wrapper'})
        # for option in search_data.find_all("option"):
        #    search_info[option['value']] = option['label']
        search_info["80000712"] = "Breakfast"
        search_info["80000713"] = "Brunch"
        search_info["80000714"] = "Dinner"
        search_info["80000717"] = "Lunch"
        search_info["06:30:00"] = "6:30 AM"
        search_info["07:00:00"] = "7:00 AM"
        search_info["07:30:00"] = "7:30 AM"
        search_info["08:00:00"] = "8:00 AM"
        search_info["08:30:00"] = "8:30 AM"
        search_info["09:00:00"] = "9:00 AM"
        search_info["09:30:00"] = "9:30 AM"
        search_info["10:00:00"] = "10:00 AM"
        search_info["10:30:00"] = "10:30 AM"
        search_info["11:00:00"] = "11:00 AM"
        search_info["11:30:00"] = "11:30 AM"
        search_info["12:00:00"] = "12:00 PM"
        search_info["12:30:00"] = "12:30 PM"
        search_info["13:00:00"] = "1:00 PM"
        search_info["13:30:00"] = "1:30 PM"
        search_info["14:00:00"] = "2:00 PM"
        search_info["14:30:00"] = "2:30 PM"
        search_info["15:00:00"] = "3:00 PM"
        search_info["15:30:00"] = "3:30 PM"
        search_info["16:00:00"] = "4:00 PM"
        search_info["16:30:00"] = "4:30 PM"
        search_info["17:00:00"] = "5:00 PM"
        search_info["17:30:00"] = "5:30 PM"
        search_info["18:00:00"] = "6:00 PM"
        search_info["18:30:00"] = "6:30 PM"
        search_info["19:00:00"] = "7:00 PM"
        search_info["19:30:00"] = "7:30 PM"
        search_info["20:00:00"] = "8:00 PM"
        search_info["20:30:00"] = "8:30 PM"
        search_info["21:00:00"] = "9:00 PM"
        search_info["21:30:00"] = "9:30 PM"
        search_info["22:00:00"] = "10:00 PM"
        search_info["22:30:00"] = "10:30 PM"

        return search_info

    def get_party_size(self):
        """
        Get the valid search party size => values from disney dining page
        """

        # dining_page = self.get_dining_data()

        search_info = OrderedDict()
        # search_data = dining_page.find('span', {"id": 'partySize-wrapper'})
        # for option in search_data.find_all("option"):
        #    search_info[option['label']] = option['value']
        for x in range(50):
            search_info[str(x + 1)] = str(x + 1)

        return search_info
