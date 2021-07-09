"""Some console related functions"""

from common.constants import bcolors
from objects import glob
import random


def printServerStartHeader(asciiArt):
	"""
	Print server start header with optional ascii art

	asciiArt -- if True, will print ascii art too
	"""

	if asciiArt:
		DaColour = random.choice([bcolors.BLUE, bcolors.YELLOW, bcolors.PINK, bcolors.RED, bcolors.GREEN])
		printColored(r""" __       ______   _________  ______      
/_/\     /_____/\ /________/\/_____/\     
\:\ \    \::::_\/_\__.::.__\/\::::_\/_    
 \:\ \    \:\/___/\  \::\ \   \:\/___/\   
  \:\ \____\::___\/_  \::\ \   \_::._\:\  
   \:\/___/\\:\____/\  \::\ \    /____\:\ 
    \_____\/ \_____\/   \__\/    \_____\/""", DaColour)

	printColored("# lets - The RealistikOsu! Score Server", bcolors.BLUE)
	printColored("# This is a fork of the LETS score server created by the Ripple Team.", bcolors.BLUE)


def printNoNl(string):
	"""
	Print string without new line at the end

	string -- string to print
	"""

	print(string, end="")


def printColored(string, color):
	"""
	Print colored string

	string -- string to print
	color -- see bcolors.py
	"""

	print("{}{}{}".format(color, string, bcolors.ENDC))


def printError():
	"""Print error text FOR LOADING"""

	printColored("Error", bcolors.RED)


def printDone():
	"""Print error text FOR LOADING"""

	printColored("Done", bcolors.GREEN)


def printWarning():
	"""Print error text FOR LOADING"""

	printColored("Warning", bcolors.YELLOW)

def printGetScoresMessage(message):
	printColored("[get_scores] {}".format(message), bcolors.PINK)

def printSubmitModularMessage(message):
	printColored("[submit_modular] {}".format(message), bcolors.YELLOW)

def printBanchoConnectMessage(message):
	printColored("[bancho_connect] {}".format(message), bcolors.YELLOW)

def printGetReplayMessage(message):
	printColored("[get_replay] {}".format(message), bcolors.PINK)

def printMapsMessage(message):
	printColored("[maps] {}".format(message), bcolors.PINK)

def printRippMessage(message):
	printColored("[ripp] {}".format(message), bcolors.GREEN)

# def printRippoppaiMessage(message):
# 	printColored("[rippoppai] {}".format(message), bcolors.GREEN)

def printWifiPianoMessage(message):
	printColored("[wifipiano] {}".format(message), bcolors.GREEN)

def printDebugMessage(message):
	printColored("[debug] {}".format(message), bcolors.BLUE)

def printScreenshotsMessage(message):
	printColored("[screenshots] {}".format(message), bcolors.YELLOW)

def printApiMessage(module, message):
	printColored("[{}] {}".format(module, message), bcolors.GREEN)
