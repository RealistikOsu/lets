import tornado.gen
import tornado.web

from common.sentry import sentry
from common.web import requestsManager
from common.web import cheesegull
from common.log import logUtils as log
from constants import exceptions
from common.ripple import userUtils

try:
	from realistik.user_utils import verify_password
except ImportError:
	# Use ripples one.
	from common.ripple.userUtils import checkLogin as verify_password

MODULE_NAME = "direct_np"
class handler(requestsManager.asyncRequestHandler):
	"""
	Handler for /web/osu-search-set.php
	"""
	@tornado.web.asynchronous
	@tornado.gen.engine
	@sentry.captureTornado
	def asyncGet(self):
		output = ""
		try:
			username = self.get_argument("u")
			password = self.get_argument("h")
			user_id = userUtils.getID(username)

			if not verify_password(user_id, password):
				raise exceptions.loginFailedException(MODULE_NAME, username)

			# Get data by beatmap id or beatmapset id
			if "b" in self.request.arguments:
				_id = self.get_argument("b")
				data = cheesegull.getBeatmap(_id)
			elif "s" in self.request.arguments:
				_id = self.get_argument("s")
				data = cheesegull.getBeatmapSet(_id)
			else:
				raise exceptions.invalidArgumentsException(MODULE_NAME)

			log.info("Requested osu!direct np: {}/{}".format("b" if "b" in self.request.arguments else "s", _id))

			# Make sure cheesegull returned some valid data
			if data is None or len(data) == 0:
				raise exceptions.osuApiFailException(MODULE_NAME)

			# Write the response
			output = cheesegull.toDirectNp(data) + "\r\n"
		except (exceptions.invalidArgumentsException, exceptions.osuApiFailException, KeyError):
			output = ""
		except exceptions.loginFailedException:
			output = "error: pass"
		finally:
			self.write(output)