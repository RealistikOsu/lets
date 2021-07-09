import imghdr
import os
import sys
import traceback
from imghdr import test_jpeg, test_png

import tornado.gen
import tornado.web
from raven.contrib.tornado import SentryMixin

from common.log import logUtils as log
from common.ripple import userUtils
from common.web import requestsManager
from constants import exceptions
from common import generalUtils
from objects import glob
from common.sentry import sentry

try:
	from realistik.user_utils import verify_password
except ImportError:
	# Use ripples one.
	from common.ripple.userUtils import checkLogin as verify_password

BASE_PATH = glob.conf.config["server"]["screenshotspath"] + "/{}.jpg"

MODULE_NAME = "screenshot"
class handler(requestsManager.asyncRequestHandler):
	"""
	Handler for /web/osu-screenshot.php
	"""
	@tornado.web.asynchronous
	@tornado.gen.engine
	@sentry.captureTornado
	def asyncPost(self):
		try:
			if glob.debug:
				requestsManager.printArguments(self)

			# Make sure screenshot file was passed
			if "ss" not in self.request.files:
				raise exceptions.invalidArgumentsException(MODULE_NAME)

			# Check user auth because of sneaky people
			if not requestsManager.checkArguments(self.request.arguments, ["u", "p"]):
				raise exceptions.invalidArgumentsException(MODULE_NAME)
			username = self.get_argument("u")
			password = self.get_argument("p")
			ip = self.getRequestIP()
			userID = userUtils.getID(username)
			if not verify_password(userID, password):
				raise exceptions.loginFailedException(MODULE_NAME, username)
			if not userUtils.checkBanchoSession(userID, ip):
				raise exceptions.noBanchoSessionException(MODULE_NAME, username, ip)

			# Rate limit
			if glob.redis.get("lets:screenshot:{}".format(userID)) is not None:
				return self.write("no")
			glob.redis.set("lets:screenshot:{}".format(userID), 1, 60)

			while os.path.exists(path := BASE_PATH.format(generalUtils.randomString(8))): pass
			
			# Check if the filesize is not ridiculous. Through my checking I
			# have discovered all screenshots on rosu are below 500kb.
			if sys.getsizeof(self.request.files["ss"][0]["body"]) > 500000:
				return self.write("filesize")
			
			# Check if the file contents are actually fine (stop them uploading eg videos).
			if (not test_jpeg(self.request.files["ss"][0]["body"], 0))\
			and (not test_png(self.request.files["ss"][0]["body"], 0)):
				return self.write("unknownfiletype")

			# Write screenshot file to screenshots folder
			with open(path, "wb") as f:
				f.write(self.request.files["ss"][0]["body"])

			# Output
			log.info("New screenshot ({})".format(path))

			# Dirty method.
			ss_ting = path.removeprefix(glob.conf.config["server"]["screenshotspath"])
			# Return screenshot link
			self.write("{}/ss{}".format(glob.conf.config["server"]["serverurl"], ss_ting))
		except exceptions.need2FAException:
			pass
		except exceptions.invalidArgumentsException:
			pass
		except exceptions.loginFailedException:
			pass