"""
oppai interface for ripple 2 / LETS
AUTO VERSION YESSSSS
"""
import json
import os
import subprocess

from common.constants import gameModes
from common.log import logUtils as log
from common.ripple import scoreUtils
from constants import exceptions
from helpers import mapsHelper

# constants
MODULE_NAME = "autoppai"
UNIX = True if os.name == "posix" else False

def fixPath(command):
	"""
	Replace / with \ if running under WIN32

	commnd -- command to fix
	return -- command with fixed paths
	"""
	if UNIX:
		return command
	return command.replace("/", "\\")


class OppaiError(Exception):
	def __init__(self, error):
		self.error = error

class oppai:
	"""
	Oppai cacalculator
	"""
	# __slots__ = ["pp", "score", "acc", "mods", "combo", "misses", "stars", "beatmap", "map"]

	def __init__(self, __beatmap, __score = None, acc = 0, mods = 0, tillerino = False, combo: int = -1):
		"""
		Set oppai params.

		__beatmap -- beatmap object
		__score -- score object
		acc -- manual acc. Used in tillerino-like bot. You don't need this if you pass __score object
		mods -- manual mods. Used in tillerino-like bot. You don't need this if you pass __score object
		tillerino -- If True, self.pp will be a list with pp values for 100%, 99%, 98% and 95% acc. Optional.
		combo -- The maximum combo achieved by the user, used for PP api. Optional. Set to -1 for FC.
		"""
		# Default values
		self.pp = None
		self.score = None
		self.acc = 0
		self.mods = 0
		self.combo = combo	#FC
		self.misses = 0
		self.stars = 0
		self.tillerino = tillerino
		# AP only has std lol
		self.gameMode = gameModes.STD

		# Beatmap object
		self.beatmap = __beatmap

		# If passed, set everything from score object
		if __score is not None:
			self.score = __score
			self.acc = self.score.accuracy * 100
			self.mods = self.score.mods
			self.combo = self.score.maxCombo
			self.misses = self.score.cMiss
		else:
			# Otherwise, set acc and mods from params (tillerino)
			self.acc = acc
			self.mods = mods

		# Calculate pp
		log.debug("oppai-auto ~> Initialized oppai diffcalc")
		self.calculatePP()

	@staticmethod
	def _runOppaiProcess(command):
		log.debug("oppai-auto ~> running {}".format(command))
		process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		try:
			output = json.loads(process.stdout.decode("utf-8", errors="ignore"))
			if "code" not in output or "errstr" not in output:
				raise OppaiError("No code in json output")
			if output["code"] != 200:
				raise OppaiError("oppai-auto error {}: {}".format(output["code"], output["errstr"]))
			if "pp" not in output or "stars" not in output:
				raise OppaiError("No pp/stars entry in oppai-auto json output")
			pp = output["pp"]
			stars = output["stars"]

			log.debug("oppai-auto ~> full output: {}".format(output))
			log.debug("oppai-auto ~> pp: {}, stars: {}".format(pp, stars))
		except (json.JSONDecodeError, IndexError, OppaiError) as e:
			raise OppaiError(e)
		return pp, stars

	def calculatePP(self):
		"""
		Calculate total pp value with oppai and return it

		return -- total pp
		"""
		# Set variables
		self.pp = None
		try:
			# Build .osu map file path
			mapFile = mapsHelper.cachedMapPath(self.beatmap.beatmapID)
			log.debug("oppai-auto ~> Map file: {}".format(mapFile))
			mapsHelper.cacheMap(mapFile, self.beatmap)

			# Use only mods supported by oppai
			modsFixed = self.mods & 5983

			# Check gamemode
			if self.gameMode != gameModes.STD and self.gameMode != gameModes.TAIKO:
				raise exceptions.unsupportedGameModeException()

			command = "./pp/oppai-ap/oppai {}".format(mapFile)
			if not self.tillerino:
				# force acc only for non-tillerino calculation
				# acc is set for each subprocess if calculating tillerino-like pp sets
				if self.acc > 0:
					command += " {acc:.2f}%".format(acc=self.acc)
			if self.mods > 0:
				command += " +{mods}".format(mods=scoreUtils.readableMods(modsFixed))
			if self.combo >= 0:
				command += " {combo}x".format(combo=self.combo)
			if self.misses > 0:
				command += " {misses}xm".format(misses=self.misses)
			if self.gameMode == gameModes.TAIKO:
				command += " -taiko"
			command += " -ojson"

			# Calculate pp
			if not self.tillerino:
				# self.pp, self.stars = self._runOppaiProcess(command)
				temp_pp, self.stars = self._runOppaiProcess(command)
				if (self.gameMode == gameModes.TAIKO and self.beatmap.starsStd > 0 and temp_pp > 800) or \
					self.stars > 50:
					# Invalidate pp for bugged taiko converteds and bugged inf pp std maps
					self.pp = 0
				else:
					self.pp = temp_pp
			else:
				pp_list = []
				for acc in [100, 99, 98, 95]:
					temp_command = command
					temp_command += " {acc:.2f}%".format(acc=acc)
					pp, self.stars = self._runOppaiProcess(temp_command)

					# If this is a broken converted, set all pp to 0 and break the loop
					if self.gameMode == gameModes.TAIKO and self.beatmap.starsStd > 0 and pp > 800:
						pp_list = [0, 0, 0, 0]
						break

					pp_list.append(pp)
				self.pp = pp_list

			log.debug("oppai-auto ~> Calculated PP: {}, stars: {}".format(self.pp, self.stars))
		except OppaiError:
			log.error("oppai-auto ~> oppai-ng error!")
			self.pp = 0
		except exceptions.osuApiFailException:
			log.error("oppai-auto ~> osu!api error!")
			self.pp = 0
		except exceptions.unsupportedGameModeException:
			log.error("oppai-auto ~> Unsupported gamemode")
			self.pp = 0
		except Exception as e:
			log.error("oppai-auto ~> Unhandled exception: {}".format(str(e)))
			self.pp = 0
			raise
		finally:
			log.debug("oppai-auto ~> Shutting down, pp = {}".format(self.pp))
