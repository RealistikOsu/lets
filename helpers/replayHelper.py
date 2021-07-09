import os

from common import generalUtils
from constants import exceptions, dataTypes
from common.constants import mods
from helpers import binaryHelper, generalHelper
from objects import glob

RELAX_OFFSET = 1073741823
AP_OFFSET = 2000000000
RX_SUFFIX = "_relax"
AP_SUFFIX = "_ap"
VN_SUFFIX = ""

def buildFullReplay(scoreID=None, scoreData=None, rawReplay=None):
    if all(v is None for v in (scoreID, scoreData)) or all(v is not None for v in (scoreID, scoreData)):
        raise AttributeError("Either scoreID or scoreData must be provided, not neither or both")

    if scoreID:
        scoreID = int(scoreID)
        if RELAX_OFFSET < scoreID < AP_OFFSET:
            table_suffix = RX_SUFFIX
        elif scoreID > AP_OFFSET:
            table_suffix = AP_SUFFIX
        else: table_suffix = VN_SUFFIX
    # Use mods value.
    else:
        if (replay_mods := int(scoreData["mods"])) & mods.RELAX:
            table_suffix = RX_SUFFIX
        elif replay_mods & mods.RELAX2:
            table_suffix = AP_SUFFIX
        else: table_suffix = VN_SUFFIX

    if scoreData is None:
        scoreData = glob.db.fetch(
            f"SELECT scores{table_suffix}.*, users.username FROM scores{table_suffix} LEFT JOIN users ON scores{table_suffix}.userid = users.id "
            f"WHERE scores{table_suffix}.id = %s",
            (scoreID,)
        )
    else:
        scoreID = scoreData["id"]
    if scoreData is None or scoreID is None:
        raise exceptions.scoreNotFoundError()

    if rawReplay is None:
        # Make sure raw replay exists
        fileName = "{}{}/replay_{}.osr".format(glob.conf.config["server"]["replayspath"], table_suffix, scoreID)
        if not os.path.isfile(fileName):
            raise FileNotFoundError()

        # Read raw replay
        with open(fileName, "rb") as f:
            rawReplay = f.read()

    # Calculate missing replay data
    rank = generalUtils.getRank(int(scoreData["play_mode"]), int(scoreData["mods"]), int(scoreData["accuracy"]),
                                int(scoreData["300_count"]), int(scoreData["100_count"]), int(scoreData["50_count"]),
                                int(scoreData["misses_count"]))
    magicHash = generalUtils.stringMd5(
        "{}p{}o{}o{}t{}a{}r{}e{}y{}o{}u{}{}{}".format(int(scoreData["100_count"]) + int(scoreData["300_count"]),
                                                      scoreData["50_count"], scoreData["gekis_count"],
                                                      scoreData["katus_count"], scoreData["misses_count"],
                                                      scoreData["beatmap_md5"], scoreData["max_combo"],
                                                      "True" if int(scoreData["full_combo"]) == 1 else "False",
                                                      scoreData["username"], scoreData["score"], rank,
                                                      scoreData["mods"], "True"))
    # Add headers (convert to full replay)
    fullReplay = binaryHelper.binaryWrite([
        [scoreData["play_mode"], dataTypes.byte],
        [20150414, dataTypes.uInt32],
        [scoreData["beatmap_md5"], dataTypes.string],
        [scoreData["username"], dataTypes.string],
        [magicHash, dataTypes.string],
        [scoreData["300_count"], dataTypes.uInt16],
        [scoreData["100_count"], dataTypes.uInt16],
        [scoreData["50_count"], dataTypes.uInt16],
        [scoreData["gekis_count"], dataTypes.uInt16],
        [scoreData["katus_count"], dataTypes.uInt16],
        [scoreData["misses_count"], dataTypes.uInt16],
        [scoreData["score"], dataTypes.uInt32],
        [scoreData["max_combo"], dataTypes.uInt16],
        [scoreData["full_combo"], dataTypes.byte],
        [scoreData["mods"], dataTypes.uInt32],
        [0, dataTypes.byte],
        [generalHelper.toDotTicks(int(scoreData["time"])), dataTypes.uInt64],
        [rawReplay, dataTypes.rawReplay],
        [0, dataTypes.uInt32],
        [scoreData['id'], dataTypes.uInt64],
    ])

    # Return full replay
    return fullReplay
