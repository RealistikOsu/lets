import os

import tornado.gen
import tornado.web

from common.log import logUtils as log
from common.web import requestsManager
from common.sentry import sentry
from common.ripple import userUtils
from objects import glob
# Custom module go brr
try:
	from realistik.user_utils import verify_password
except ImportError:
	# Use ripples one.
	from common.ripple.userUtils import checkLogin as verify_password

REPLAY_PATH_BASE = glob.conf.config["server"]["replayspath"] + "{}/replay_{}.osr"
MODULE_NAME = "get_replay"

# Score ID offsets, so that we dont run ridiculous amounts of queries.
RELAX_OFFSET = 1073741823
AP_OFFSET = 2000000000
BASE_QUERY = (
	"SELECT play_mode, userid FROM scores{} WHERE id = %s LIMIT 1"
)

class handler(requestsManager.asyncRequestHandler):
	"""A rewrittten replay handler for RealisitkOsu, without any ridiculous
	misuse of SQL.
	
	Handles `/web/osu-getreplay.php`
	"""
	@tornado.web.asynchronous
	@tornado.gen.engine
	@sentry.captureTornado
	def asyncGet(self):
		"""The actual handler."""

		# Argument Verification.
		if not requestsManager.checkArguments(self.request.arguments, ("u", "h", "c")):
			return self.write("no")
		
		# Set variables.
		username = self.get_argument("u")
		#p_hash = self.get_argument("h")
		replay_id = int(self.get_argument("c"))

		# Work out scores table from ID.
		suffix = ""
		# Relax replay
		if RELAX_OFFSET < replay_id < AP_OFFSET: suffix = "_relax"
		elif replay_id > AP_OFFSET: suffix = "_ap"

		# Grab data on the gamer that did this.
		play_db = glob.db.fetch(
			BASE_QUERY.format(suffix),
			(replay_id,)
		)

		if play_db: userUtils.incrementReplaysWatched(
			play_db["userid"], play_db["play_mode"]
		)

		rp_path = REPLAY_PATH_BASE.format(suffix, replay_id)
		if not os.path.exists(rp_path):
			log.warning(f"Attempted to serve non-existant replay ({rp_path}) to {username}")
			return self.write("no")

		# We send them le replay.
		log.info(f"Served {rp_path} to {username}.")
		with open(rp_path, "rb") as f: return self.write(f.read())
