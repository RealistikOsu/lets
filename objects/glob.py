import personalBestCache
import personalBestCacheRX
import personalBestCacheAP
import userStatsCache
import userStatsCacheRX
import userStatsCacheAP
from common.ddog import datadogClient
from common.files import fileBuffer, fileLocks
from common.web import schiavo

try:
	with open("version") as f:
		VERSION = f.read().strip()
except:
	VERSION = "Unknown"
ACHIEVEMENTS_VERSION = 1

DATADOG_PREFIX = "lets"
db = None
redis = None
conf = None
application = None
pool = None
pascoa = {}
achievements = []

debug = False
sentry = False

no_check_md5s = {}
clan_cache = None

def add_nocheck_md5(md5: str, status: int) -> None:
	"""Adds a beatmap MD5 to the list of md5s not to call osu api for.
	Also makes sure the list doesn't get too large so we dont run out of
	memory.
	"""

	no_check_md5s[md5] = status

	# What did I just make?
	if len(no_check_md5s) > 5000: del no_check_md5s[tuple(no_check_md5s)[0]]

# Cache and objects
fLocks = fileLocks.fileLocks()
userStatsCache = userStatsCache.userStatsCache()
userStatsCacheRX = userStatsCacheRX.userStatsCacheRX()
userStatsCacheAP = userStatsCacheAP.userStatsCacheAP()
personalBestCache = personalBestCache.personalBestCache()
personalBestCacheRX = personalBestCacheRX.personalBestCacheRX()
personalBestCacheAP = personalBestCacheAP.personalBestCacheAP()
fileBuffers = fileBuffer.buffersList()
dog = datadogClient.datadogClient()
schiavo = schiavo.schiavo()
achievementClasses = {}

# Additional modifications
COMMON_VERSION_REQ = "1.2.1"
try:
	with open("common/version") as f:
		COMMON_VERSION = f.read().strip()
except:
	COMMON_VERSION = "Unknown"
