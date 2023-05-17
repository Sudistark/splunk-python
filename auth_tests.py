import splunk.auth
import unittest
from splunk.util import pytest_mark_skip_conditional
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

@pytest_mark_skip_conditional(reason="SPL-175665: Probably a regression or functional test now")
class MainTest(unittest.TestCase):

    def testSingleWrites(self):
        key = splunk.auth.getSessionKey('admin', 'changeme')

        self.assertTrue(key)

    def testGetNotExistUserByName(self):
        key = splunk.auth.getSessionKey('admin', 'changeme')

        info = splunk.auth.getUser('idontexist', sessionKey=key)
        self.assertEqual(info, None)

    def testGetUserByName(self):
        key = splunk.auth.getSessionKey('admin', 'changeme')

        info = splunk.auth.getUser('admin', sessionKey=key)
        self.assertEqual(info['name'], 'admin')
        self.assertEqual(info['realname'], 'Administrator')
        self.assertTrue('admin' in info['roles'])
        self.assertTrue('system' in info['eai:acl']['owner'])

    def testGetRole(self):
        key = splunk.auth.getSessionKey('admin', 'changeme')

        info = splunk.auth.getRole('admin', sessionKey=key)
        self.assertTrue('main' in info['imported_srchIndexesDefault'])
        self.assertTrue('power' in info['imported_roles'])
        self.assertTrue('system' in info['eai:acl']['sharing'])
        self.assertTrue('search' in info['imported_capabilities'])

    def testGetListUsers(self):
        key = splunk.auth.getSessionKey('admin', 'changeme')

        users = listUsers(sessionKey=key)
        self.assertTrue(len(users) > 0)
        self.assertTrue('admin' in users)

    def testGetListRoles(self):
        key = splunk.auth.getSessionKey('admin', 'changeme')

        roles = splunk.auth.listRoles(sessionKey=key)
        self.assertTrue(len(roles) > 0)
        self.assertTrue('admin' in roles)

    def testGetRemoteUserByName(self):
        key = splunk.auth.getSessionKey('admin', 'changeme')

        info = splunk.auth.getUser('admin', sessionKey=key)
        self.assertEqual(info['name'], 'admin')
        self.assertEqual(info['realname'], 'Administrator')
        self.assertTrue('admin' in info['roles'])
        self.assertTrue('system' in info['eai:acl']['owner'])

    def testGetRemoteListUsers(self):
        key = splunk.auth.getSessionKey('admin', 'changeme')

        users = splunk.auth.listUsers(sessionKey=key)
        self.assertTrue(len(users) > 0)
        self.assertTrue('admin' in users)

    def testGetRemoteListRoles(self):
        key = splunk.auth.getSessionKey('admin', 'changeme')

        roles = splunk.auth.listRoles(sessionKey=key)
        self.assertTrue(len(roles) > 0)
        self.assertTrue('admin' in roles)


class GetCurrentUserSuite(unittest.TestCase):
    def setUp(self):
        class MockEntity:
            properties = {}
        self.mock_entity = MockEntity()

    def tearDown(self):
        self.mock_entity = None

    def test_is_current_user_admin_for_admin(self):
        with patch('splunk.auth.getCurrentUser') as getCurrentUserMock, \
            patch('splunk.entity.getEntity') as getEntityMock:

            getCurrentUserMock.return_value = { 'name': 'admin' }
            setattr(self.mock_entity, 'properties', { 'capabilities': ['admin_all_objects'] })
            getEntityMock.return_value = self.mock_entity
            self.assertTrue(splunk.auth.is_current_user_admin())

    def test_is_current_user_admin_for_non_admin(self):
        with patch('splunk.auth.getCurrentUser') as getCurrentUserMock, \
            patch('splunk.entity.getEntity') as getEntityMock:

            getCurrentUserMock.return_value = { 'name': 'non_admin' }
            setattr(self.mock_entity, 'properties', { 'capabilities': [] })
            getEntityMock.return_value = self.mock_entity
            self.assertFalse(splunk.auth.is_current_user_admin())

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MainTest)
    unittest.TextTestRunner(verbosity=2).run(suite)

    suite = unittest.TestLoader().loadTestsFromTestCase(GetCurrentUserSuite)
    unittest.TextTestRunner(verbosity=2).run(suite)
