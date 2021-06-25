"""Unit tests for infobloxdns"""
import unittest
import infobloxdns
from unittest import mock


class TestCorpDnsUtility(unittest.TestCase):
    """Unit tests for CorpDnsUtility"""
    def setUp(self):
        fakedomain = 'tests.local'
        fakeserver = 'testserver.tests.local'
        fakeuser = 'testuser'
        fakepass = 'testpasswd'
        self.dns = infobloxdns.CorpDnsUtility(fakedomain, fakeserver, fakeuser, fakepass)

    def test_validate_ip(self):
        # Test good input.
        self.dns._validate_ip('10.10.10.10')

        # Test bad input (invalid octet digits).
        with self.assertRaises(ValueError):
            self.dns._validate_ip('999.999.999.999')

        # Test bad input (invalid octet characters).
        with self.assertRaises(ValueError):
            self.dns._validate_ip('a.b.c.d')

    @mock.patch('infobloxdns.connector.Connector.get_object')
    def test_query(self, mock_get_object):
        # Test default options.
        mock_return = [{'ipv4addr': '10.10.10.10', 'name': 'testresult', '_ref': 'fake_ref_obj'}]
        mock_get_object.return_value = mock_return
        result = self.dns.query('record:a')
        self.assertTrue(mock_get_object.called_with(obj_type='record:a', paging=True))
        self.assertEqual(result, mock_return)

        # Test with payload.
        mock_get_object.reset_mock()
        result = self.dns.query('record:a', {'name': 'testresult'})
        self.assertTrue(mock_get_object.called_with(obj_type='record:a', payload={'name': 'testresult'}, paging=True))
        self.assertEqual(result, mock_return)

        # Test with paging disabled.
        mock_get_object.reset_mock()
        result = self.dns.query('record:a', paging=False)
        self.assertTrue(mock_get_object.called_with(obj_type='record:a'))
        self.assertEqual(result, mock_return)

        # Test with return fields.
        mock_get_object.reset_mock()
        result = self.dns.query('record:a', return_fields=['a', 'b', 'c'])
        self.assertTrue(mock_get_object.called_with(obj_type='record:a', paging=True, return_fields=['a', 'b', 'c']))
        self.assertEqual(result, mock_return)

    @mock.patch('infobloxdns.connector.Connector.create_object')
    def test_create(self, mock_create_object):
        mock_return = 'fake_ref_obj'
        mock_create_object.return_value = mock_return
        result = self.dns.create('record:a', {'ipv4addr': '10.10.10.10', 'name': 'fakename'})
        self.assertTrue(mock_create_object.called_with(
            obj_type='record:a',
            payload={'ipv4addr': '10.10.10.10', 'name': 'fakename'}
        ))
        self.assertEqual(result, mock_return)

    @mock.patch('infobloxdns.connector.Connector.update_object')
    def test_update(self, mock_update_object):
        mock_return = 'fake_ref_obj'
        mock_update_object.return_value = mock_return
        result = self.dns.update('fake_ref_obj', {'ipv4addr': '10.10.10.10'})
        self.assertTrue(mock_update_object.called_with(
            obj_type='record:a',
            payload={'ipv4addr': '10.10.10.10'}
        ))
        self.assertEqual(result, mock_return)

    @mock.patch('infobloxdns.connector.Connector.delete_object')
    def test_delete(self, mock_delete_object):
        mock_return = 'fake_ref_obj'
        mock_delete_object.return_value = mock_return
        result = self.dns.delete('fake_ref_obj')
        self.assertTrue(mock_delete_object.called_with('fake_ref_obj'))
        self.assertEqual(result, mock_return)

    @mock.patch('infobloxdns.connector.Connector.get_object')
    def test_get_a_record(self, mock_get_object):
        # Test good successful call.
        mock_return = [{'ipv4addr': '10.10.10.10', 'name': 'testresult', '_ref': 'fake_ref_obj'}]
        mock_get_object.return_value = mock_return
        result = self.dns.get_a_record('10.10.10.10')
        self.assertTrue(mock_get_object.called_with('record:a', payload={'ipv4addr': '10.10.10.10'}))
        self.assertEqual(result, mock_return)

        # Test bad call (exception handling)
        mock_get_object.reset_mock()
        mock_get_object.side_effect = Exception("This is a fake exception!")
        result = self.dns.get_a_record('10.10.10.20')
        self.assertTrue(mock_get_object.called_with('record:a', payload={'ipv4addr': '10.10.10.20'}))
        self.assertIsNone(result)

    @mock.patch('infobloxdns.connector.Connector.get_object')
    def test_get_ptr_record(self, mock_get_object):
        # Test good successful call.
        mock_return = [{'ipv4addr': '10.10.10.10', 'ptrdname': 'fakename', '_ref': 'fake_ref_obj'}]
        mock_get_object.return_value = mock_return
        result = self.dns.get_ptr_record('10.10.10.10')
        self.assertTrue(mock_get_object.called_with('record:ptr', payload={'ipv4addr': '10.10.10.10'}))
        self.assertEqual(result, mock_return)

        # Test bad call (exception handling)
        mock_get_object.reset_mock()
        mock_get_object.side_effect = Exception("This is a fake exception!")
        result = self.dns.get_ptr_record('10.10.10.20')
        self.assertTrue(mock_get_object.called_with('record:ptr', payload={'ipv4addr': '10.10.10.20'}))
        self.assertIsNone(result)

    @mock.patch('infobloxdns.connector.Connector.create_object')
    def test_create_a_record(self, mock_create_object):
        # Test good, no comment.
        mock_return = 'fake_ref_obj'
        mock_create_object.return_value = mock_return
        result = self.dns.create_a_record('fake_hostname', '10.10.10.10')
        self.assertTrue(mock_create_object.called_with(
            'record:a',
            payload={
                'ipv4addr': '10.10.10.10',
                'name': 'fake_hostname.tests.local',
                'comment': 'Created by CorpDnsUtility'
            }
        ))
        self.assertEqual(result, mock_return)

        # Test good with comment.
        mock_create_object.reset_mock()
        result = self.dns.create_a_record('second_fake', '10.10.10.20', 'A fake comment')
        self.assertTrue(mock_create_object.called_with(
            'record:a',
            payload={'ipv4addr': '10.10.10.20', 'name': 'second_fake.tests.local', 'comment': 'A fake comment'}
        ))
        self.assertEqual(result, mock_return)

        # Test bad IP input
        mock_create_object.reset_mock()
        with self.assertRaises(ValueError):
            result = self.dns.create_a_record('third_fake', '123.456.789.123')
            self.assertTrue(mock_create_object.not_called)
            self.assertIsNone(result)

    @mock.patch('infobloxdns.connector.Connector.create_object')
    def test_create_ptr_record(self, mock_create_object):
        # Test good no comment.
        mock_return = 'fake_ref_obj'
        mock_create_object.return_value = mock_return
        result = self.dns.create_ptr_record('fake_host', '10.10.10.10')
        self.assertTrue(mock_create_object.called_with(
            'record:ptr',
            payload={
                'ipv4addr': '10.10.10.10',
                'ptrdname': 'fake_host.tests.local',
                'comment': 'Created by CorpDnsUtility'
            }
        ))
        self.assertEqual(result, mock_return)

        # Test good with comment.
        mock_create_object.reset_mock()
        result = self.dns.create_ptr_record('second_fake_host', '10.10.10.20', 'Some comment')
        self.assertTrue(mock_create_object.called_with(
            'record:ptr',
            payload={
                'ipv4addr': '10.10.10.20',
                'ptrdname': 'second_fake_host.tests.local',
                'comment': 'Some comment'
            }
        ))
        self.assertEqual(result, mock_return)

        # Test bad IP input.
        mock_create_object.reset_mock()
        with self.assertRaises(ValueError):
            result = self.dns.create_ptr_record('third_fake', '123.456.789.123')
            self.assertTrue(mock_create_object.not_called)
            self.assertIsNone(result)

    @mock.patch('infobloxdns.connector.Connector.update_object')
    def test_update_a_record(self, mock_update_object):
        # Test good IP update.
        mock_return = 'fake_ref_obj'
        mock_update_object.return_value = mock_return
        result = self.dns.update_a_record('fake_ref_obj', ip_address='10.10.10.10')
        self.assertTrue(mock_update_object.called_with(
            'fake_ref_obj',
            payload={'ipv4addr': '10.10.10.10', 'comment': 'Updated by CorpDnsUtility'}
        ))
        self.assertEqual(result, mock_return)

        # Test bad IP update.
        mock_update_object.reset_mock()
        with self.assertRaises(ValueError):
            result = self.dns.update_a_record('fake_ref_obj', ip_address='123.456.789.123')
            self.assertTrue(mock_update_object.not_called)
            self.assertIsNone(result)

        # Test good hostname update.
        mock_update_object.reset_mock()
        result = self.dns.update_a_record('fake_ref_obj', hostname='fake_host')
        self.assertTrue(mock_update_object.called_with(
            'fake_ref_obj',
            payload={
                'name': 'fake_host.tests.local',
                'comment': 'Updated by CorpDnsUtility'
            }
        ))
        self.assertEqual(result, mock_return)

        # Test update with custom comment.
        mock_update_object.reset_mock()
        result = self.dns.update_a_record('fake_ref_obj', hostname='second_fake', comment='Some Comment')
        self.assertTrue(mock_update_object.called_with(
            'fake_ref_obj',
            payload={
                'name': 'second_fake.tests.local',
                'comment': 'Some Comment'
            }
        ))
        self.assertEqual(result, mock_return)

        # Test bad call (not enough args)
        mock_update_object.reset_mock()
        with self.assertRaises(ValueError):
            self.dns.update_a_record('fake_ref_obj')
            self.assertTrue(mock_update_object.not_called)

    @mock.patch('infobloxdns.connector.Connector.update_object')
    def test_update_ptr_record(self, mock_update_object):
        # Test good IP update.
        mock_return = 'fake_ref_obj'
        mock_update_object.return_value = mock_return
        result = self.dns.update_ptr_record('fake_ref_obj', ip_address='10.10.10.10')
        self.assertTrue(mock_update_object.called_with(
            'fake_ref_obj',
            payload={
                'ipv4addr': '10.10.10.10',
                'comment': 'Updated by CorpDnsUtility'
            }
        ))
        self.assertEqual(result, mock_return)

        # Test bad IP update.
        mock_update_object.reset_mock()
        with self.assertRaises(ValueError):
            result = self.dns.update_ptr_record('fake_ref_obj', ip_address='123.456.789.123')
            self.assertTrue(mock_update_object.not_called)
            self.assertIsNone(result)

        # Test good hostname update.
        mock_update_object.reset_mock()
        result = self.dns.update_ptr_record('fake_ref_obj', hostname='fake_host')
        self.assertTrue(mock_update_object.called_with(
            'fake_ref_obj',
            payload={
                'ptrdname': 'fake_host.tests.local',
                'comment': 'Updated by CorpDnsUtility'
            }
        ))
        self.assertEqual(result, mock_return)

        # Test good hostname update with comment.
        mock_update_object.reset_mock()
        result = self.dns.update_ptr_record('fake_ref_obj', hostname='second_fake', comment='Some comment')
        self.assertTrue(mock_update_object.called_with(
            'fake_ref_obj',
            payload={
                'ptrdname': 'second_fake.tests.local',
                'comment': 'Some comment'
            }
        ))
        self.assertEqual(result, mock_return)

        mock_update_object.reset_mock()
        with self.assertRaises(ValueError):
            result = self.dns.update_ptr_record('fake_ref_obj')
            self.assertTrue(mock_update_object.not_called)
            self.assertIsNone(result)

    @mock.patch('infobloxdns.CorpDnsUtility.delete')
    def test_delete_a_record(self, mock_delete):
        mock_return = 'fake_ref_obj'
        mock_delete.return_value = mock_return
        with self.assertWarns(PendingDeprecationWarning):
            result = self.dns.delete_a_record('fake_ref_obj')
            self.assertTrue(mock_delete.called_with('fake_ref_obj'))
            self.assertEqual(result, mock_return)

    @mock.patch('infobloxdns.CorpDnsUtility.delete')
    def test_delete_ptr_record(self, mock_delete):
        mock_return = 'fake_ref_obj'
        mock_delete.return_value = mock_return
        with self.assertWarns(PendingDeprecationWarning):
            result = self.dns.delete_ptr_record('fake_ref_obj')
            self.assertTrue(mock_delete.called_with('fake_ref_obj'))
            self.assertEqual(result, mock_return)

    @mock.patch('infobloxdns.connector.Connector.get_object')
    def test_bulk_fetch_records(self, mock_get_object):
        # Test good call.
        mock_return = [
            {'ipv4addr': '10.10.10.10', 'name': 'fake_name.tests.local'},
            {'ipv4addr': '10.10.10.20', 'name': 'second_fake.tests.local'}
        ]
        mock_get_object.return_value = mock_return
        result = self.dns.bulk_fetch_records('tests.local', 'A')
        self.assertTrue(mock_get_object.called_with('record:a', payload={'zone': 'tests.local'}, paging=True))
        self.assertEqual(result, mock_return)

        # Test good call with return fields.
        mock_get_object.reset_mock()
        return_fields = ['field1', 'field2', 'field3']
        result = self.dns.bulk_fetch_records('tests.local', 'PTR', return_fields=return_fields)
        self.assertTrue(mock_get_object.called_with(
            'record:ptr',
            payload={'zone': 'tests.local'},
            paging=True,
            return_fields=return_fields
        ))
        self.assertEqual(result, mock_return)

        # Test bad call.
        mock_get_object.reset_mock()
        mock_get_object.side_effect = Exception('This is a fake exception...')
        result = self.dns.bulk_fetch_records('tests.local', 'CNAME')
        self.assertTrue(mock_get_object.called_with('record:cname', payload={'zone': 'tests.local'}, paging=True))
        self.assertIsNone(result)

    @mock.patch('infobloxdns.connector.Connector.get_object')
    def test_fetch_zones(self, mock_get_object):
        # Test good call
        mock_return = [{'zone': 'zone1', '_ref': 'fake_ref_1'}, {'zone': 'zone2', '_ref': 'fake_ref_2'}]
        mock_get_object.return_value = mock_return
        result = self.dns.fetch_zones()
        self.assertTrue(mock_get_object.called_with('zone_auth', paging=True))
        self.assertEqual(result, mock_return)

        # Test failed call.
        mock_get_object.reset_mock()
        mock_get_object.side_effect = Exception('Fake exception')
        result = self.dns.fetch_zones()
        self.assertTrue(mock_get_object.called_with('zone_auth', paging=True))
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
