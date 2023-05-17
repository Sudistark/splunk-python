from __future__ import absolute_import
import unittest
import re


def get_restricted_jquery_files_regex():
    blocklist_restricted_jquery_files = [
        # Dashboard 1.0
        '/build/pages/enterprise/dashboard\.js',
        '/build/pages/enterprise/.*\.web\.js',
        '/build/pages/dark/dashboard\.js',
        '/build/pages/dark/.*\.web\.js',
        '/build/pages/lite/dashboard\.js',
        '/build/pages/lite/.*\.web\.js',

        # HTML Dashboards
        '/build/simplexml/.*',
        '/js/build/simplexml/.*',
        '/js/build/simplexml.min/.*',
        '/js/build/splunkjs/.*',
        '/js/build/splunkjs.min/.*',

        # jQuery files
        '/js/contrib/jquery/.*',
        '/js/contrib/jquery\-2\.1\.0\.js',
        '/js/contrib/jquery\-2\.1\.0\.min\.js',
        '/js/contrib/jquery\-1\.8\.2\.js',
        '/js/contrib/jquery\-1\.8\.2\.min\.js',
    ]
    regex_string = '^((?!(%s)).)*$' % '|'.join(blocklist_restricted_jquery_files)
    restricted_jquery_files_regex = re.compile(regex_string, re.IGNORECASE)
    return restricted_jquery_files_regex


# Tests

class RestrictJQueryDashboardV1RegexSuite(unittest.TestCase):
    def test_dashboard_v1_enterprise_theme_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/build/pages/enterprise/dashboard.js'),
            'should not match enterprise mode dashboards 1.0 JS file')

    def test_dashboard_v1_lite_theme_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/build/pages/lite/dashboard.js'),
            'should not match lite mode dashboards 1.0 JS file')

    def test_dashboard_v1_dark_theme_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/build/pages/dark/dashboard.js'),
            'should not match dark mode dashboards 1.0 JS file')

    def test_dashboard_v1_lazy_loaded_files(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/build/pages/enterprise/1.web.js'),
            'should not match lazy loaded modules from web folder')

    def test_should_ignore_case(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/build/pages/enterprise/DASHboard.js'),
            'should not match dashboard 1.0 JS file with different casing')

class RestrictJQueryHTMLDashboardRegexSuite(unittest.TestCase):
    def test_html_dashboard_index_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/build/simplexml/index.js'),
            'should not match html dashboards index.js file')

    def test_html_dashboard_lazy_loaded_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/build/simplexml/2.js'),
            'should not match lazy loaded html dashboards JS file')

    def test_html_dashboard_alternative_config_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/js/build/simplexml/config.js'),
            'should not match alternative html dashboards config.js file')

    def test_html_dashboard_alternative_lazy_loaded_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/js/build/simplexml/3.js'),
            'should not match alternative lazy loaded html dashboards JS file')

    def test_html_dashboard_minified_config_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/js/build/simplexml.min/config.js'),
            'should not match minified html dashboards config.js file')

    def test_html_dashboard_minified_lazy_loaded_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/js/build/simplexml.min/4.js'),
            'should not match minified html dashboards config.js file')


class RestrictJQuerySourceFileRegexSuite(unittest.TestCase):
    def test_jquery_2_1_0_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/js/contrib/jquery-2.1.0.js'),
            'should not match jquery 2.1.0 source file')

    def test_jquery_2_1_0_minified_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/js/contrib/jquery-2.1.0.min.js'),
            'should not match minified jquery 2.1.0 source file')

    def test_jquery_1_8_2_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/js/contrib/jquery-1.8.2.js'),
            'should not match jquery 1.8.2 source file')

    def test_jquery_1_8_2_minified_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/js/contrib/jquery-1.8.2.min.js'),
            'should not match minified jquery 1.8.2 source file')

    def test_jquery_1_8_3_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/js/contrib/jquery/jquery.js'),
            'should not match jquery 1.8.3 source file')


class NonRestrictedJQueryAssetsSuite(unittest.TestCase):
    def test_dashboard_v1_1_index_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNotNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/build/pages/enterprise/dashboard_1.1.js'),
            'should match dashboard 1.1 JS file')

    def test_dashboard_v1_1_lazy_loaded_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNotNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/build/pages/enterprise/2.js'),
            'should match dashboard 1.1 lazy loaded JS file')

    def test_layout_api_file(self):
        regex = get_restricted_jquery_files_regex()
        self.assertIsNotNone(
            re.match(
                regex, 'http://www.testingurls.splunk/static/statichash/build/api/layout.js'),
            'should match layout api file')


if __name__ == '__main__':
    # run tests
    restrict_jquery_dashboard_v1_regex_suite = unittest.TestLoader().loadTestsFromTestCase(RestrictJQueryDashboardV1RegexSuite)
    unittest.TextTestRunner(verbosity=2).run(restrict_jquery_dashboard_v1_regex_suite)

    restrict_jquery_html_dashboard_regex_suite = unittest.TestLoader().loadTestsFromTestCase(RestrictJQueryHTMLDashboardRegexSuite)
    unittest.TextTestRunner(verbosity=2).run(restrict_jquery_html_dashboard_regex_suite)

    restrict_jquery_source_file_regex_suite = unittest.TestLoader().loadTestsFromTestCase(RestrictJQuerySourceFileRegexSuite)
    unittest.TextTestRunner(verbosity=2).run(restrict_jquery_html_dashboard_regex_suite)

    non_restricted_jquery_assets_suite = unittest.TestLoader().loadTestsFromTestCase(NonRestrictedJQueryAssetsSuite)
    unittest.TextTestRunner(verbosity=2).run(non_restricted_jquery_assets_suite)
