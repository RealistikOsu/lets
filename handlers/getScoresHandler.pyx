import json
import tornado.gen
import tornado.web

from objects import beatmap
from objects import scoreboard
from objects import scoreboardRelax
from objects import scoreboardAuto
from common.constants import privileges
from common.log import logUtils as log
from common.ripple import userUtils
from common.web import requestsManager
from constants import exceptions, rankedStatuses
from objects import glob
from common.constants import mods
from common.sentry import sentry
# I love benchmarks.
from helpers.realistikh import Timer

# Custom module go brr
try:
	from realistik.user_utils import verify_password
except ImportError:
	# Use ripples one.
	log.warning("Using Ripple pass check!")
	from common.ripple.userUtils import checkLogin as verify_password

cdef str MODULE_NAME = "get_scores"
class handler(requestsManager.asyncRequestHandler):
	"""
	Handler for /web/osu-osz2-getscores.php
	"""
	@tornado.web.asynchronous
	@tornado.gen.engine
	@sentry.captureTornado
	def asyncGet(self):
		t = Timer()
		t.start()
		cdef str ip
		cdef str md5
		cdef str fileName
		cdef str beatmapSetID
		cdef str gameMode
		cdef str username
		cdef str password
		cdef int scoreboardType 
		cdef int scoreboardVersion
		cdef int privs

		# Scoreboard type
		cdef bint isDonor
		cdef bint country
		cdef bint friends
		cdef int modsFilter
		cdef int mods
		cdef str fileNameShort
		cdef str data
		cdef int userID
		try:
			# Get request ip
			ip = self.getRequestIP()

			# Print arguments
			if glob.debug:
				requestsManager.printArguments(self)

			# TODO: Maintenance check

			# Check required arguments
			if not requestsManager.checkArguments(
					self.request.arguments,
					("c", "f", "i", "m", "us", "v", "vv", "mods")
			):
				raise exceptions.invalidArgumentsException(MODULE_NAME)

			# GET parameters
			md5 = self.get_argument("c")
			fileName = self.get_argument("f")
			beatmapSetID = self.get_argument("i")
			gameMode = self.get_argument("m")
			username = self.get_argument("us")
			password = self.get_argument("ha")
			scoreboardType = int(self.get_argument("v"))
			scoreboardVersion = int(self.get_argument("vv"))

			if len(md5) != 32: 
				log.error(f"{username} sent an invalid MD5!")
				raise exceptions.invalidArgumentsException(MODULE_NAME)
			
			# Not submitted/need update cache.
			if md5 in glob.no_check_md5s: return self.write(f"{glob.no_check_md5s[md5]}|false")

			# Login and ban check
			userID = userUtils.getID(username)
			if not userID: raise exceptions.loginFailedException(MODULE_NAME, userID)
			if not verify_password(userID, password):
				raise exceptions.loginFailedException(MODULE_NAME, username)

			# Hax check
			if "a" in self.request.arguments:
				if int(self.get_argument("a")) == 1:
					log.warning("Found AQN folder on user {} ({})".format(username, userID), "cm")
					userUtils.setAqn(userID)


			privs = userUtils.getPrivileges(userID)
			# Scoreboard type
			isDonor = privs  & privileges.USER_DONOR > 0
			country = scoreboardType == 4
			friends = scoreboardType == 3 and isDonor
			modsFilter = -1
			mods = int(self.get_argument("mods"))

			if scoreboardType == 2:
				# Mods leaderboard, replace mods (-1, every mod) with "mods" GET parameters
				modsFilter = int(self.get_argument("mods"))


			# Console output
			fileNameShort = fileName[:32]+"..." if len(fileName) > 32 else fileName[:-4]

			# Create beatmap object and set its data
			bmap = beatmap.beatmap(md5, beatmapSetID, gameMode, fileName=fileName)
			bmap.saveFileName(fileName)

			# Create leaderboard object, link it to bmap and get all scores
			if mods & 128:
					sboard = scoreboardRelax.scoreboardRelax(
					username, gameMode, bmap, setScores=True, country=country, mods=modsFilter, friends=friends
					)
			elif mods & 8192:
				sboard = scoreboardAuto.scoreboardAuto(
					username, gameMode, bmap, setScores=True, country=country, mods=modsFilter, friends=friends
				)
			else:
					sboard = scoreboard.scoreboard(
						username, gameMode, bmap, setScores=True, country=country, mods=modsFilter, friends=friends
					)

			# Data to return
			data = bmap.getData(sboard.totalScores, scoreboardVersion) + sboard.getScoresData()
			self.write(data)

			# Check if it needs update or is not submitted so we dont get exploited af.
			if bmap.rankedStatus in (rankedStatuses.NOT_SUBMITTED, rankedStatuses.NEED_UPDATE):
				glob.add_nocheck_md5(md5, bmap.rankedStatus)

			# Datadog stats
			glob.dog.increment(glob.DATADOG_PREFIX+".served_leaderboards")
			t.end()
			log.info(f"Served leaderboards for {fileNameShort} ({md5}) | {t.time_str()}")
		except exceptions.invalidArgumentsException:
			self.write("error: meme")
		except exceptions.userBannedException:
			self.write("error: ban")
		except exceptions.loginFailedException:
			self.write("error: pass")