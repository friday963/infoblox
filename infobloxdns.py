import ipaddress
import logging
from infoblox_client import connector
from typing import Dict, NoReturn, Union, List
from requests import urllib3


class CorpDnsUtility:
    def __init__(self, domain, infoblox_server, username, password, dns_view="default", wapi_version='2.9'):
        self.log = logging.getLogger('infobloxdns.CorpDnsUtility')
        self.server = infoblox_server
        self.user = username
        self.password = password
        self.dns_view = dns_view
        self.domain = domain
        if self.domain[0] == ".":
            self.domain = self.domain.rstrip(".")
        opts = {"host": self.server, "username": self.user, "password": self.password, 'wapi_version': wapi_version}
        self.conn = connector.Connector(opts)
        urllib3.disable_warnings()

    def _validate_ip(self, ip: str) -> NoReturn:
        """
        Validate an input to verify it is a real IP address.

        Args:
            ip (str): [The input to validate.]

        Returns:
            None

        Raises:
            ValueError
        """
        try:
            ipaddress.ip_address(ip)
        except Exception as e:
            self.log.error(f"Error parsing IP address: {e}", exc_info=True)
            raise ValueError(f"Invalid IP address provided: {ip}")

    def query(
            self,
            object_type: str,
            payload: Union[None, Dict] = None,
            paging: bool = True,
            return_fields: Union[None, List] = None
    ) -> Union[NoReturn, List[Dict]]:
        """
        A generic method for querying Infoblox API for objects.

        Args:
            object_type (str): The object type to query. List of object types available in API documentation.
            payload (dict, optional): The query payload for searching/filtering results.
            paging (bool): The paging option allows results higher than the default max (1000).
            return_fields (list, optional): A list of fields to return. Fields vary based on object type, refer to API documentation.

        Returns:
            List[dict]: A list of dictionaries with each list item representing a single result.
        """
        params = {'obj_type': object_type, 'paging': paging}
        if payload:
            params['payload'] = payload
        if return_fields:
            params['return_fields'] = return_fields
        result = self.conn.get_object(**params)
        return result

    def create(
            self,
            object_type: str,
            payload: Dict,
    ) -> str:
        """
        A generic create method for creating objects in the Infoblox API.

        Args:
            object_type (str): The object type to create.
            payload (dict): The payload for creating the object. Fields vary based on object type, refer to API documentation.

        Returns:
            str: The reference id for the created object.
        """
        params = {'obj_type': object_type, 'payload': payload}
        result = self.conn.create_object(**params)
        return result

    def update(
            self,
            ref: str,
            payload: Dict
    ) -> str:
        """
        A generic update method for updating objects in the Infoblox API.

        Args:
            ref (str): The reference ID for the object to update.
            payload (dict): A dictionary containing the fields to update. Fields vary based on object type, refer to API documentation.

        Returns:
            str: The reference ID for the created object.
        """
        params = {'ref': ref, 'payload': payload}
        result = self.conn.update_object(**params)
        return result

    def delete(self, reference_obj: str) -> str:
        """
        A generic method for deleting objects in the Infoblox API.

        Args:
             reference_obj (str): The reference object for the object to delete.

        Returns:
              str: The reference object of the deleted object.
        """
        result = self.conn.delete_object(reference_obj)
        return result

    def get_a_record(self, ip_address: str) -> Union[List[Dict], NoReturn]:
        """
        Look up an A record by IP address.

        Args:
             ip_address (str): The IP address for the record to look up.

        Returns:
            List[Dict] (optional): A list of dictionaries with each list item representing an A record.
        """
        try:
            results = self.conn.get_object("record:a", payload={"ipv4addr": ip_address})
            return results
        except Exception as e:
            self.log.warning(f"Error looking up A record: {e}", exc_info=True)
            return None

    def get_ptr_record(self, ip_address: str) -> Union[List[Dict], NoReturn]:
        """
        Look up a PTR record by IP address.

        Args:
            ip_address (str): The IP address for the record to look up.

        Returns:
            List[Dict] (optional): A list of dictionaries with each list item representing a PTR record.
        """
        try:
            results = self.conn.get_object(
                "record:ptr", payload={"ipv4addr": ip_address}
            )
            return results
        except Exception as e:
            self.log.warning(f"Error looking up PTR record: {e}", exc_info=True)
            return None

    def create_a_record(self, hostname: str, ip_address: str, comment: str = None) -> str:
        """create an A record based on the hostname + domain and associated IP address.

        Args:
            hostname (str): [Hostname without anything appended]
            ip_address (str): [IP address of the device]
            comment (str, optional): [Populuate this field if you want a custom comment on the new record]

        Returns:
            str: [Returns a reference object for the updated object.]
        """
        self._validate_ip(ip_address)
        proper_fqdn = (hostname + "." + self.domain).lower()
        if comment is None:
            comment = "Created by CorpDnsUtility"
        result = self.conn.create_object(
            "record:a", payload={"ipv4addr": ip_address, "name": proper_fqdn, "comment": comment}
        )
        return result

    def create_ptr_record(self, hostname: str, ip_address: str, comment: str = None) -> str:
        """create an a PTR record based on the hostname + domain and associated IP address.

        Args:
            hostname (str): [Hostname without anything appended]
            ip_address (str): [IP address of the device]
            comment (str): [Populate this field if you want a custom comment on the new record]

        Returns:
            str: [Returns a reference object for the updated object.]
        """
        self._validate_ip(ip_address)
        proper_fqdn = (hostname + "." + self.domain).lower()
        if comment is None:
            comment = "Created by CorpDnsUtility"
        result = self.conn.create_object(
            "record:ptr",
            payload={"ipv4addr": ip_address, "ptrdname": proper_fqdn, "comment": comment},
        )
        return result

    def update_a_record(
            self, reference_obj: str, hostname: str = None, ip_address: str = None, comment: str = None
    ) -> str:
        """[summary]

        Args:
            reference_obj (str): [reference object is found in the return value of an appopriate get method specifically in the _ref dict item.]
            hostname (str, optional): [Populate this field if you want to update its value, otherwise leave it blank.]. Defaults to None.
            ip_address (str, optional): [Populate this field if you want to update its value, otherwise leave it blank.]. Defaults to None.
            comment (str, optional): [Populate this field if you want a custom comment on the updated record]

        Returns:
            str: [Returns a reference object for the updated object.]
        """
        if not hostname and not ip_address:
            raise ValueError(
                "Not enough parameters provided.  Must provide at least one parameter to update."
            )
        else:
            payload = {'comment': 'Updated by CorpDnsUtility'}
            if hostname:
                proper_fqdn = (hostname + "." + self.domain).lower()
                payload["name"] = proper_fqdn
            if ip_address:
                self._validate_ip(ip_address)
                payload["ipv4addr"] = ip_address
            if comment is not None:
                payload['comment'] = comment
            result = self.conn.update_object(reference_obj, payload=payload)
            return result

    def update_ptr_record(
            self, reference_obj: str, hostname: str = None, ip_address: str = None, comment: str = None
    ):
        """[summary]

        Args:
            reference_obj (str): [reference object is found in the return value of an appopriate get method specifically in the _ref dict item.]
            hostname (str, optional): [Populate this field if you want to update its value, otherwise leave it blank.]. Defaults to None.
            ip_address (str, optional): [Populate this field if you want to update its value, otherwise leave it blank.]. Defaults to None.
            comment (str, optional): [Populate this field if you want a custom comment on the updated record]

        Returns:
            str: [Returns a reference object for the updated object.]
        """
        if not hostname and not ip_address:
            raise ValueError(
                "Not enough parameters provided.  Must provide at least one parameter to update."
            )
        else:
            payload = {'comment': 'Updated by CorpDnsUtility'}
            if hostname:
                proper_fqdn = (hostname + "." + self.domain).lower()
                payload["ptrdname"] = proper_fqdn
            if ip_address:
                self._validate_ip(ip_address)
                payload["ipv4addr"] = ip_address
            if comment is not None:
                payload["comment"] = comment
            result = self.conn.update_object(reference_obj, payload=payload)
            return result

    def delete_a_record(self, reference_obj: str) -> str:
        from warnings import warn
        warn("This method is pending deprecation. Please use CorpDnsUtility.delete_record", PendingDeprecationWarning)
        return self.delete(reference_obj)

    def delete_ptr_record(self, reference_obj: str) -> str:
        from warnings import warn
        warn("This method is pending deprecation. Please use CorpDnsUtility.delete_record", PendingDeprecationWarning)
        return self.delete(reference_obj)

    def bulk_fetch_records(
            self,
            zone: str,
            record_type: str,
            return_fields: List[str] = None
    ) -> Union[List[Dict], NoReturn]:
        """
        Fetch all records in the provided zone of the provided type.

        Args:
             zone (str): The zone to fetch records from.
             record_type (str): The type of record to fetch (example: ptr)
             return_fields (List[str]): A list of fields to return for each record.

        returns:
            List[dict]: A list of dictionaries with each item representing a single record.
        """
        payload = {'zone': zone}
        try:
            if return_fields:
                result = self.conn.get_object(
                    f"record:{record_type.lower()}",
                    payload=payload,
                    paging=True,
                    return_fields=return_fields
                )
            else:
                result = self.conn.get_object(
                    f"record:{record_type.lower()}",
                    payload=payload,
                    paging=True
                )
            return result
        except Exception as e:
            self.log.warning(f"Error fetching records: {e}", exc_info=True)
            return None

    def fetch_zones(self) -> Union[List[Dict], NoReturn]:
        """
        Fetch all DNS zones. Requires read permission on all zones.

        Returns:
             List[Dict]: A list of dictionaries with each item representing a zone.
        """
        try:
            result = self.conn.get_object('zone_auth', paging=True)
            return result
        except Exception as e:
            self.log.warning(f"Error fetching zones: {e}", exc_info=True)
            return None
