# Made by RealisitkDash. If you yoink this, keep this comment. License says it.
from objects import glob
from typing import Dict, Union

class ClanCache:
    """Tackles probably the 2nd most inefficient part of lets, the clan
    system. Prior to this, for each score, LETS would run an SQL query to grab
    each user's clan per score per lb and I thought that was meme worthy.
    Rosu encounters CPU usage spikes to this has to be done I am afraid.
    
    Cool system tho, accurately keeps track of clans while maintaining
    exact same functionality and better performance.
    
    **This only caches clan tags per user.**
    """

    def __init__(self) -> None:
        """Sets defaults for the cache."""

        # Indexed user_id: clan_tag
        self._cached_tags: Dict[int, str] = {}
    
    def bulk_cache(self) -> None:
        """Caches all clan members within the database.
        
        Note:
            This fully wipes the current cache and refreshes it.
        """

        self._cached_tags.clear()

        # Grab all clan memberships from db.
        clans_db = glob.db.fetchAll(
            "SELECT uc.user AS u, c.tag AS tag FROM user_clans uc "
            "INNER JOIN clans c ON uc.clan = c.id"
        )

        # Save all to cache.
        for mem in clans_db:
            self._cached_tags[mem["u"]] = mem["tag"]
    
    def cache_individual(self, user_id: int) -> None:
        """Caches an individual's clan (singular person) to cache. Meant for
        handling clan updates.
        
        Args:
            user_id (int): The user for who to update the cached tag for.
        """

        # Delete them if they already had a value cached.
        try: del self._cached_tags[user_id]
        except KeyError: pass

        # Grab their tag.
        clan_db = glob.db.fetch(
            "SELECT c.tag AS tag FROM clans c INNER JOIN "
            "user_clans uc ON c.id = uc.clan WHERE uc.user = %s LIMIT 1",
            (user_id,)
        )

        if not clan_db: return # Nothing... Keep it empty and get will just return noen.

        # cache their tag.
        self._cached_tags[user_id] = clan_db["tag"]
    
    def get(self, user_id: int) -> Union[str, None]:
        """Returns the clan tag for the given user.
        
        Args:
            user_id (int): The user you want to grab the clan tag for.
        """

        return self._cached_tags.get(user_id)
    
    @property
    def cached_count(self) -> int:
        """Number of tags cached."""

        return len(self._cached_tags)
    
    def __len__(self) -> int: return self.cached_count
