import tornado.gen
import tornado.web

from common.ripple import userUtils
from common.web import requestsManager
from helpers.discord_hooks import Webhook
from objects import glob
from helpers import generalHelper

try:
	from realistik.user_utils import verify_password
except ImportError:
	# Use ripples one.
	from common.ripple.userUtils import checkLogin as verify_password

# TODO: Rewrite this....
MODULE_NAME = "lastFMHandler"
class handler(requestsManager.asyncRequestHandler):
    """
    Handler for /web/lastfm.php

    Handler by @KotRikD
    Enum values by @Enjuu and @Cyuubi
    """
    @tornado.web.asynchronous
    @tornado.gen.engine
    def asyncGet(self):
        if glob.conf.config["discord"]["enable"] == True:
            webhook = Webhook(glob.conf.config["discord"]["ahook"],
                      color=0xadd8e6,
                      footer="Caught with Client Anticheat")

        ip = self.getRequestIP()
        if not requestsManager.checkArguments(self.request.arguments, ["b", "ha", "us"]):
            return self.write("error: gimme more arguments")

        username = self.get_argument("us")
        password = self.get_argument("ha")
        beatmap_ban = self.get_argument("b", None)

        userID = userUtils.getID(username)
        if userID == 0:
            return self.write("error: user is unknown")
        if not verify_password(userID, password):
            return self.write("error: youre the bad guy....")
        if not userUtils.checkBanchoSession(userID, ip):
            raise self.write("error: what if... we are the bad guys?")
        if not beatmap_ban or beatmap_ban and not beatmap_ban.startswith("a"):
            return self.write("-3")

        arguments_cheat = beatmap_ban[1:]
        if not arguments_cheat.isdigit():
            return self.write("error: srsly?")

        arguments_cheat = int(arguments_cheat)
        # Let's try found something
        cheat_id = generalHelper.getHackByFlag(arguments_cheat)
        if glob.conf.config["discord"]["enable"] == True:
            webhook.set_title(title=f"Caught some cheater {username} ({userID})")
            if type(cheat_id) is str:
                webhook.set_desc(f'This body caught with flag {arguments_cheat}\nIn enuming: {cheat_id}')
            else:
                webhook.set_desc(f'This body caught with undefined flag {arguments_cheat}')

            webhook.post()

        return self.write("-3")
