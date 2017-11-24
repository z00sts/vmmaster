# coding: utf-8
import os
import unittest
import subprocess

from StringIO import StringIO
from multiprocessing.pool import ThreadPool
from os import setsid, killpg
from signal import SIGTERM
from ConfigParser import RawConfigParser
from lode_runner import dataprovider

from core.utils.network_utils import get_free_port
from tests.helpers import get_microapp_address
from tests.config import Config


@dataprovider(Config.platforms)
class TestCaseWithMicroApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app_port = get_free_port()
        cls.p = cls.start_app(cls.app_port)

        path = os.path.dirname(os.path.realpath(__file__))
        config_parser = RawConfigParser()
        config_parser.read("%s/tests/config" % path)
        config_parser.set("Network", "addr", "http://{}:{}".format(get_microapp_address(), cls.app_port))
        with open('%s/tests/config' % path, 'wb') as configfile:
            config_parser.write(configfile)

    @classmethod
    def tearDownClass(cls):
        killpg(cls.p.pid, SIGTERM)

    @staticmethod
    def start_app(app_port):
        return subprocess.Popen([
            "gunicorn",
            "--log-level=warning",
            "-w 2",
            "-b 0.0.0.0:{}".format(app_port),
            "tests.functional.app.views:app"
            ], preexec_fn=setsid
        )

    def setUp(self):
        self.loader = unittest.TestLoader()
        self.runner = unittest.TextTestRunner(stream=StringIO())
        self.stream = StringIO()

    def test_positive_case(self, platform):
        from tests.test_normal import TestPositiveCase
        TestPositiveCase.platform = platform
        suite = self.loader.loadTestsFromTestCase(TestPositiveCase)
        result = self.runner.run(suite)
        self.assertEqual(2, result.testsRun, result.errors)
        self.assertEqual(1, len(result.errors), result.errors)
        self.assertEqual(0, len(result.failures), result.failures)
        self.assertEqual("test_error", result.errors[0][0]._testMethodName)

    def test_two_same_tests_parallel_run(self, platform):
        from tests.test_normal import TestParallelSessions1, TestParallelSessions2
        TestParallelSessions1.platform = platform
        TestParallelSessions2.platform = platform
        # TODO: Добавить проверку параллельности запусков тестов
        suite1 = unittest.TestSuite()
        suite1.addTest(TestParallelSessions1("test"))
        suite2 = unittest.TestSuite()
        suite2.addTest(TestParallelSessions2("test"))

        pool = ThreadPool(2)
        deffered1 = pool.apply_async(self.runner.run, args=(suite1,))
        deffered2 = pool.apply_async(self.runner.run, args=(suite2,))
        deffered1.wait()
        deffered2.wait()
        result1 = deffered1.get()
        result2 = deffered2.get()

        self.assertEqual(1, result1.testsRun, result1.errors)
        self.assertEqual(1, result2.testsRun, result2.errors)
        self.assertEqual(0, len(result1.errors), result1.errors)
        self.assertEqual(0, len(result2.errors), result2.errors)
        self.assertEqual(0, len(result1.failures), result1.failures)
        self.assertEqual(0, len(result2.failures), result2.failures)


@dataprovider(Config.platforms)
class TestCase(unittest.TestCase):
    def setUp(self):
        self.loader = unittest.TestLoader()
        self.runner = unittest.TextTestRunner(stream=StringIO())
        self.stream = StringIO()

    def test_run_script_on_session_creation(self, platform):
        from tests.test_normal import TestRunScriptOnSessionCreation
        TestRunScriptOnSessionCreation.platform = platform
        suite = self.loader.loadTestsFromTestCase(
            TestRunScriptOnSessionCreation)
        result = self.runner.run(suite)
        self.assertEqual(1, result.testsRun, result.errors)
        self.assertEqual(0, len(result.errors), result.errors)
        self.assertEqual(0, len(result.failures), result.failures)

    def test_environment_variables(self, platform):
        if ":" not in platform:
            # only docker endpoints
            return
        from tests.test_normal import TestEnvironmentVariables
        TestEnvironmentVariables.platform = platform
        suite = self.loader.loadTestsFromTestCase(TestEnvironmentVariables)
        result = self.runner.run(suite)
        self.assertEqual(1, result.testsRun, result.errors)
        self.assertEqual(0, len(result.errors), result.errors)
        self.assertEqual(0, len(result.failures), result.failures)

    @unittest.skip("Error \"Connection reset by peer\" in apt-get-scripts on random openstack endpoints")
    def test_run_script_with_install_package_on_session_creation(self, platform):
        from tests.test_normal import TestRunScriptWithInstallPackageOnSessionCreation
        TestRunScriptWithInstallPackageOnSessionCreation.platform = platform
        suite = self.loader.loadTestsFromTestCase(
            TestRunScriptWithInstallPackageOnSessionCreation)
        result = self.runner.run(suite)
        self.assertEqual(1, result.testsRun, result.errors)
        self.assertEqual(0, len(result.errors), result.errors)
        self.assertEqual(0, len(result.failures), result.failures)

    @unittest.skip("Error \"Connection reset by peer\" in apt-get-scripts on random openstack endpoints")
    def test_run_script_tests_parallel_run(self, platform):
        from tests.test_normal import TestParallelSlowRunScriptOnSession1, TestParallelSlowRunScriptOnSession2
        TestParallelSlowRunScriptOnSession1.platform = platform
        TestParallelSlowRunScriptOnSession2.platform = platform
        suite1 = unittest.TestSuite()
        suite1.addTest(TestParallelSlowRunScriptOnSession1("test"))
        suite2 = unittest.TestSuite()
        suite2.addTest(TestParallelSlowRunScriptOnSession2("test"))

        pool = ThreadPool(2)
        deffered1 = pool.apply_async(self.runner.run, args=(suite1,))
        deffered2 = pool.apply_async(self.runner.run, args=(suite2,))
        deffered1.wait()
        deffered2.wait()
        result1 = deffered1.get()
        result2 = deffered2.get()

        self.assertEqual(1, result1.testsRun, result1.errors)
        self.assertEqual(1, result2.testsRun, result2.errors)
        self.assertEqual(0, len(result1.errors), result1.errors)
        self.assertEqual(0, len(result2.errors), result2.errors)
        self.assertEqual(0, len(result1.failures), result1.failures)
        self.assertEqual(0, len(result2.failures), result2.failures)
