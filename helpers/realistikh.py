# A class I copy paste throughout pretty much my all projects lmfao.
import time
from objects import glob

class Timer:
    """A simple timer class used to time the execution of code."""

    def __init__(self):
        """Initialises timer for use."""
        self.start_time = 0
        self.end_time = 0

    def start(self) -> None:
        """Begins the timer."""
        self.start_time = time.time()

    def end(self) -> float:
        """Ends the timer and returns final time."""
        self.end_time = time.time()
        return self.end_time - self.start_time

    def get_difference(self) -> float:
        """Returns the difference between start and end"""
        return self.end_time - self.start_time

    def reset(self) -> None:
        """Resets the timer."""
        self.end_time = 0
        self.start_time = 0

    def ms_return(self) -> float:
        """Returns difference in 2dp ms."""
        return round((self.end_time - self.start_time) * 1000, 2)
    
    def time_str(self) -> str:
        """Returns a nicely formatted timing result."""

        # This function already takes a timer so its a match in heaven lmfao.
        return time_str(self)
    
def time_str(timer: Timer) -> str:
    """If time is in ms, returns ms value. Else returns rounded seconds value."""

    if t := timer.end() < 1:
        time_str = f"{timer.ms_return()}ms"
    else:
        time_str = f"{round(t,2)}s"
    return time_str

def fetch_achievements_db():
    """Fetches all achievements from db on startup."""

    # For fella who wants to use our new achievements system. You need database with content to fetch
    # you can use cmyuis gulag one as our system was based on it. 
    # But for security reasons RealistikOsu will never share their database.
    achievements = glob.db.fetchAll("SELECT * FROM new_achievements")
    for achievement in achievements:
        condition = eval(f"lambda score, mode_vn, playcount: {achievement.pop('cond')}")
        glob.achievements.append(Achievement(
            _id= achievement['id'],
            file= achievement['file'],
            name= achievement['name'],
            desc= achievement['desc'],
            condition= condition
        ))
    log.info(f"Loaded {len(glob.achievements)} new achievements to cache!")
